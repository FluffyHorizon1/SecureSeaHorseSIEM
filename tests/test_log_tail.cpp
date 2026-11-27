// Unit tests for Linux offset tracking, first-run baseline, and rotation.
#include "test_util.h"
#include "log_tail.h"

#include <filesystem>
#include <fstream>
#include <string>
#include <unistd.h>
#include <sys/stat.h>

static void write_file(const std::string& path, const std::string& body, bool append = false) {
    std::ofstream f(path, append ? std::ios::app : std::ios::trunc);
    f << body;
}

int main() {
    std::printf("test_log_tail\n");
    auto dir = std::filesystem::temp_directory_path() /
               ("seahorse_tail_" + std::to_string(getpid()));
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    const std::string log = (dir / "auth.log").string();
    const std::string state = (dir / "log_tail.state").string();

    write_file(log, "old line 1\nold line 2\n");
    LogTailTracker t(state);

    // First sight: baseline at EOF, no historical flood.
    auto r1 = t.read_new(log, 65536);
    CHECK(r1.baseline);
    CHECK(r1.data.empty());
    t.commit(r1.cursor);

    // Append two new lines; only those should appear.
    write_file(log, "Failed password for alice from 192.0.2.1 port 22 ssh2\n", true);
    write_file(log, "Accepted publickey for alice from 192.0.2.1 port 22 ssh2\n", true);
    auto r2 = t.read_new(log, 65536);
    CHECK(!r2.baseline);
    CHECK(r2.data.find("Failed password") != std::string::npos);
    CHECK(r2.data.find("Accepted publickey") != std::string::npos);
    CHECK(r2.data.find("old line") == std::string::npos);
    t.commit(r2.cursor);

    // Re-read with no new data.
    auto r3 = t.read_new(log, 65536);
    CHECK(r3.data.empty());

    // Rotation: rename to .1, new file with a new line. Leftover on .1
    // should be drained if we append to the old file first, then rotate.
    write_file(log, "leftover-on-rotated\n", true);
    std::filesystem::rename(log, log + ".1");
    write_file(log, "new-file-line\n");
    auto r4 = t.read_new(log, 65536);
    CHECK(r4.rotated);
    CHECK(r4.data.find("leftover-on-rotated") != std::string::npos);
    CHECK(r4.data.find("new-file-line") != std::string::npos);
    t.commit(r4.cursor);

    // State file survives reload.
    {
        LogTailTracker t2(state);
        auto r5 = t2.read_new(log, 65536);
        CHECK(r5.data.empty());
        CHECK(!r5.baseline);
    }

    // copytruncate-style shrink: same inode, smaller size, reset to 0.
    // The replacement must be shorter than the committed offset.
    write_file(log, "x\n");
    auto r6 = t.read_new(log, 65536);
    CHECK(r6.rotated);
    CHECK(r6.data.find("x") != std::string::npos);

    auto lines = split_log_lines("a\n\nb\r\nc\n");
    CHECK(lines.size() == 3);
    CHECK(lines[0] == "a" && lines[1] == "b" && lines[2] == "c");

    std::filesystem::remove_all(dir);
    TEST_MAIN_RETURN();
}
