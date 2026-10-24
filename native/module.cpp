// VaultMount - Zygisk module.
//
// App side (in the app process):
//   preAppSpecialize  : still root; check rules.conf, remember if this package is allowed.
//   postAppSpecialize : ask the root companion to mount the vault into THIS process's mount
//                       namespace, then wait for the answer before app code runs.
// Companion side (root, separate process):
//   fork() a single-threaded child -> setns(app mnt ns) -> bind mount vault subfolder over
//   /storage/emulated/<user>/<target>.

#include <fcntl.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <android/log.h>

#include <fstream>
#include <string>
#include <vector>

#include "zygisk.hpp"

#define LOG_TAG "VaultMount"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static constexpr const char *VAULT_DIR = "/data/adb/vault";
static constexpr const char *RULES_FILE = "/data/adb/vault/rules.conf";
static constexpr const char *PLAIN_DIR = "/data/adb/vault/plain";

struct Rule {
    std::string pkg, target, sub;
};

static std::vector<Rule> load_rules() {
    std::vector<Rule> out;
    std::ifstream f(RULES_FILE);
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        size_t a = line.find('|');
        size_t b = line.find('|', a == std::string::npos ? 0 : a + 1);
        if (a == std::string::npos || b == std::string::npos) continue;
        Rule r{line.substr(0, a), line.substr(a + 1, b - a - 1), line.substr(b + 1)};
        // Reject path traversal; keep everything inside the intended roots.
        if (r.target.find("..") != std::string::npos || r.sub.find("..") != std::string::npos) continue;
        if (r.pkg.empty() || r.target.empty() || r.sub.empty()) continue;
        out.push_back(r);
    }
    return out;
}

static bool write_all(int fd, const void *buf, size_t n) {
    const char *p = static_cast<const char *>(buf);
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w <= 0) return false;
        p += w;
        n -= w;
    }
    return true;
}

static bool read_all(int fd, void *buf, size_t n) {
    char *p = static_cast<char *>(buf);
    while (n) {
        ssize_t r = read(fd, p, n);
        if (r <= 0) return false;
        p += r;
        n -= r;
    }
    return true;
}

// ---------------------------------------------------------------- companion (root)

static void companion_handler(int fd) {
    uint32_t len = 0;
    int32_t uid = 0, pid = 0;
    int32_t result = -1;

    if (!read_all(fd, &len, sizeof(len)) || len == 0 || len > 256) goto done;
    {
        std::string pkg(len, '\0');
        if (!read_all(fd, &pkg[0], len) || !read_all(fd, &uid, sizeof(uid)) ||
            !read_all(fd, &pid, sizeof(pid)))
            goto done;

        // Is the vault unlocked? (fuse mount present)
        bool unlocked = false;
        {
            std::ifstream m("/proc/mounts");
            std::string l;
            std::string needle = std::string(" ") + PLAIN_DIR + " ";
            while (std::getline(m, l))
                if (l.find(needle) != std::string::npos) { unlocked = true; break; }
        }
        if (!unlocked) { result = 1; goto done; }  // locked: app just gets no vault

        // Prepare all strings BEFORE fork (no allocation in the child).
        std::vector<std::pair<std::string, std::string>> mounts;  // src, dst
        int user = uid / 100000;
        for (auto &r : load_rules()) {
            if (r.pkg != pkg) continue;
            std::string src = std::string(PLAIN_DIR) + "/" + r.sub;
            std::string dst = "/storage/emulated/" + std::to_string(user) + "/" + r.target;
            mkdir(src.c_str(), 0777);
            mounts.emplace_back(src, dst);
        }
        if (mounts.empty()) { result = 2; goto done; }

        char nspath[64];
        snprintf(nspath, sizeof(nspath), "/proc/%d/ns/mnt", pid);
        int nsfd = open(nspath, O_RDONLY | O_CLOEXEC);
        if (nsfd < 0) { result = 3; goto done; }

        pid_t child = fork();
        if (child == 0) {
            // Single-threaded child: join the app's mount namespace and bind-mount.
            int rc = 0;
            if (setns(nsfd, CLONE_NEWNS) != 0) _exit(10);
            for (auto &m : mounts) {
                if (mount(m.first.c_str(), m.second.c_str(), nullptr, MS_BIND | MS_REC, nullptr) != 0)
                    rc = 11;
            }
            _exit(rc);
        }
        close(nsfd);
        if (child < 0) { result = 4; goto done; }
        int st = 0;
        waitpid(child, &st, 0);
        result = (WIFEXITED(st) && WEXITSTATUS(st) == 0) ? 0 : 100 + WEXITSTATUS(st);
    }
done:
    write_all(fd, &result, sizeof(result));
}

// ---------------------------------------------------------------- app side

class VaultModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        const char *name = env->GetStringUTFChars(args->nice_name, nullptr);
        if (name) {
            pkg = name;
            env->ReleaseStringUTFChars(args->nice_name, name);
        }
        uid = args->uid;

        // Only apps with a rule get any further involvement; everyone else unloads.
        wanted = false;
        for (auto &r : load_rules())
            if (r.pkg == pkg) { wanted = true; break; }
        if (!wanted) api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *) override {
        if (!wanted) return;
        int fd = api->connectCompanion();
        if (fd < 0) { LOGE("no companion"); return; }

        uint32_t len = pkg.size();
        int32_t pid = getpid();
        int32_t result = -1;
        if (write_all(fd, &len, sizeof(len)) && write_all(fd, pkg.data(), len) &&
            write_all(fd, &uid, sizeof(uid)) && write_all(fd, &pid, sizeof(pid)) &&
            read_all(fd, &result, sizeof(result))) {
            LOGI("%s: mount result %d", pkg.c_str(), result);
        } else {
            LOGE("%s: companion io failed", pkg.c_str());
        }
        close(fd);
    }

private:
    zygisk::Api *api = nullptr;
    JNIEnv *env = nullptr;
    std::string pkg;
    int32_t uid = 0;
    bool wanted = false;
};

REGISTER_ZYGISK_MODULE(VaultModule)
REGISTER_ZYGISK_COMPANION(companion_handler)
