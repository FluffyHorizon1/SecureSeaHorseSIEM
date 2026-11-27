#ifndef SEAHORSE_LOG_TAIL_H
#define SEAHORSE_LOG_TAIL_H

// Offset-tracking log tailer for Linux auth/syslog files. Handles rotation
// (inode change or shrink, including copytruncate) and optional leftover
// read from path.1 when the inode moved there. First observation of a path
// baselines at EOF so a fresh agent does not flood historical logs.
//
// Windows agents do not compile this header into the scrape path
// (see win_event_log.h). Tests include it on Linux.

#include <cstdint>
#include <string>
#include <map>
#include <vector>
#include <fstream>
#include <sstream>
#include <sys/stat.h>

struct FileCursor {
    std::string path;
    uint64_t    inode  = 0;
    uint64_t    offset = 0;
};

struct TailRead {
    FileCursor  cursor;          // state to commit after a successful send
    std::string data;            // newly read bytes (may be empty on baseline)
    bool        baseline = false;
    bool        rotated  = false;
    std::string rotated_leftover; // leftover from path.1, if any (already in data)
};

class LogTailTracker {
public:
    explicit LogTailTracker(std::string state_path)
        : state_path_(std::move(state_path))
    {
        load();
    }

    const std::string& state_path() const { return state_path_; }

    TailRead read_new(const std::string& path, size_t max_bytes) {
        TailRead out;
        out.cursor.path = path;

        struct stat st {};
        if (stat(path.c_str(), &st) != 0) {
            // File not present -- keep any previous cursor so a later reappearance
            // with the same inode can resume; if unseen, leave empty.
            auto it = cursors_.find(path);
            if (it != cursors_.end()) out.cursor = it->second;
            return out;
        }

        const uint64_t ino  = static_cast<uint64_t>(st.st_ino);
        const uint64_t size = static_cast<uint64_t>(st.st_size);

        auto it = cursors_.find(path);
        if (it == cursors_.end()) {
            // First sight of this path: baseline at EOF, no historical flood.
            out.cursor.inode  = ino;
            out.cursor.offset = size;
            out.baseline = true;
            return out;
        }

        FileCursor prev = it->second;
        uint64_t start = prev.offset;

        if (prev.inode != 0 && (ino != prev.inode || size < prev.offset)) {
            out.rotated = true;
            // If logrotate moved the old file to path.1, drain the remainder.
            if (prev.inode != 0 && prev.offset > 0) {
                std::string rotated = path + ".1";
                struct stat st1 {};
                if (stat(rotated.c_str(), &st1) == 0 &&
                    static_cast<uint64_t>(st1.st_ino) == prev.inode &&
                    static_cast<uint64_t>(st1.st_size) > prev.offset) {
                    uint64_t leftover = static_cast<uint64_t>(st1.st_size) - prev.offset;
                    if (leftover > max_bytes) leftover = max_bytes;
                    std::ifstream rf(rotated, std::ios::binary);
                    if (rf) {
                        rf.seekg(static_cast<std::streamoff>(prev.offset));
                        std::string chunk(leftover, '\0');
                        rf.read(&chunk[0], static_cast<std::streamsize>(leftover));
                        chunk.resize(static_cast<size_t>(rf.gcount()));
                        out.rotated_leftover = chunk;
                        out.data.append(chunk);
                        if (max_bytes >= chunk.size()) max_bytes -= chunk.size();
                        else max_bytes = 0;
                    }
                }
            }
            start = 0;
        }

        out.cursor.inode = ino;
        if (start > size) start = 0;
        uint64_t want = (size > start) ? (size - start) : 0;
        if (want > max_bytes) want = max_bytes;

        if (want > 0) {
            std::ifstream f(path, std::ios::binary);
            if (f) {
                f.seekg(static_cast<std::streamoff>(start));
                std::string chunk(want, '\0');
                f.read(&chunk[0], static_cast<std::streamsize>(want));
                chunk.resize(static_cast<size_t>(f.gcount()));
                out.data.append(chunk);
                out.cursor.offset = start + chunk.size();
            } else {
                out.cursor.offset = start;
            }
        } else {
            out.cursor.offset = start;
        }
        return out;
    }

    void commit(const FileCursor& c) {
        if (c.path.empty()) return;
        cursors_[c.path] = c;
        save();
    }

    void load() {
        cursors_.clear();
        std::ifstream f(state_path_);
        if (!f) return;
        std::string line;
        while (std::getline(f, line)) {
            if (line.empty() || line[0] == '#') continue;
            // inode \t offset \t path  (path may contain spaces)
            auto t1 = line.find('\t');
            if (t1 == std::string::npos) continue;
            auto t2 = line.find('\t', t1 + 1);
            if (t2 == std::string::npos) continue;
            FileCursor c;
            try {
                c.inode  = static_cast<uint64_t>(std::stoull(line.substr(0, t1)));
                c.offset = static_cast<uint64_t>(std::stoull(line.substr(t1 + 1, t2 - t1 - 1)));
            } catch (...) { continue; }
            c.path = line.substr(t2 + 1);
            if (!c.path.empty()) cursors_[c.path] = c;
        }
    }

    void save() const {
        std::ofstream f(state_path_, std::ios::trunc);
        if (!f) return;
        f << "# seahorse log tail state: inode\\toffset\\tpath\n";
        for (const auto& kv : cursors_) {
            const auto& c = kv.second;
            f << c.inode << '\t' << c.offset << '\t' << c.path << '\n';
        }
    }

    const FileCursor* cursor_for(const std::string& path) const {
        auto it = cursors_.find(path);
        return it == cursors_.end() ? nullptr : &it->second;
    }

private:
    std::string state_path_;
    std::map<std::string, FileCursor> cursors_;
};

// Split a byte blob into individual lines, dropping empty ones. Keeps the
// original line text without the terminating newline.
inline std::vector<std::string> split_log_lines(const std::string& data) {
    std::vector<std::string> lines;
    size_t i = 0;
    while (i < data.size()) {
        size_t j = data.find('\n', i);
        if (j == std::string::npos) j = data.size();
        std::string line = data.substr(i, j - i);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) lines.push_back(std::move(line));
        i = (j < data.size()) ? j + 1 : data.size();
    }
    return lines;
}

#endif
