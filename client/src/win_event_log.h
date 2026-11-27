#ifndef SEAHORSE_WIN_EVENT_LOG_H
#define SEAHORSE_WIN_EVENT_LOG_H

// Windows Security-channel reader for logon events. Compiled only on _WIN32.
// Collects Event IDs 4624, 4625, 4634, 4648, 4672, 4740 regardless of Level
// (the previous scrape used Level<=3 and missed Audit Success / Information
// logon events). A persisted Evt bookmark is advanced only after a successful
// send so events are neither re-sent nor dropped on a failed cycle.
//
// First run (no bookmark file): anchor at the newest matching event and
// return no records -- same baseline behaviour as FIM / log tail.

#ifdef _WIN32

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winevt.h>
#include <string>
#include <vector>
#include <fstream>
#include <cstdint>

#include "log_batch.h"

#pragma comment(lib, "wevtapi.lib")

namespace win_event_log {

inline std::string wide_to_utf8(const wchar_t* ws, int nchars = -1) {
    if (!ws || (nchars == 0) || (nchars < 0 && ws[0] == L'\0')) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, ws, nchars, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string out(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws, nchars, &out[0], n, nullptr, nullptr);
    // WideCharToMultiByte with nchars=-1 includes the trailing NUL.
    if (nchars < 0 && !out.empty() && out.back() == '\0') out.pop_back();
    return out;
}

inline std::wstring utf8_to_wide(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0) return {};
    std::wstring out(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), &out[0], n);
    return out;
}

inline std::string load_text_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    std::string s((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    return s;
}

inline bool save_text_file(const std::string& path, const std::string& body) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f.write(body.data(), static_cast<std::streamsize>(body.size()));
    return static_cast<bool>(f);
}

inline std::string render_xml(EVT_HANDLE handle, EVT_RENDER_FLAGS flags) {
    DWORD bufUsed = 0, propCount = 0;
    EvtRender(nullptr, handle, flags, 0, nullptr, &bufUsed, &propCount);
    if (bufUsed == 0) return {};
    std::vector<wchar_t> buf(bufUsed / sizeof(wchar_t) + 1, L'\0');
    if (!EvtRender(nullptr, handle, flags, bufUsed, buf.data(), &bufUsed, &propCount))
        return {};
    return wide_to_utf8(buf.data());
}

inline EVT_HANDLE create_bookmark_from_file(const std::string& path) {
    std::string xml = load_text_file(path);
    if (xml.empty()) return EvtCreateBookmark(nullptr);
    std::wstring w = utf8_to_wide(xml);
    EVT_HANDLE h = EvtCreateBookmark(w.c_str());
    if (!h) h = EvtCreateBookmark(nullptr);
    return h;
}

// Anchor the bookmark at the newest matching event. Returns bookmark XML
// (empty if the channel had no matching events).
inline std::string baseline_bookmark(const wchar_t* channel, const wchar_t* xpath) {
    EVT_HANDLE hResults = EvtQuery(nullptr, channel, xpath,
        EvtQueryChannelPath | EvtQueryReverseDirection);
    if (!hResults) return {};
    EVT_HANDLE hEvent = nullptr;
    DWORD returned = 0;
    std::string xml;
    if (EvtNext(hResults, 1, &hEvent, 2000, 0, &returned) && hEvent) {
        EVT_HANDLE hBk = EvtCreateBookmark(nullptr);
        if (hBk) {
            EvtUpdateBookmark(hBk, hEvent);
            xml = render_xml(hBk, EvtRenderBookmark);
            EvtClose(hBk);
        }
        EvtClose(hEvent);
    }
    EvtClose(hResults);
    return xml;
}

struct PollResult {
    std::vector<std::string> events_xml;
    std::string bookmark_xml;   // persist only after a successful send
    bool baseline = false;
    bool ok = true;
};

// Query the Security channel with kWindowsAuthXPath (or the supplied XPath).
// max_events is capped at kLogBatchMaxRecords.
inline PollResult poll_security_logons(const std::string& bookmark_path,
                                       int max_events,
                                       const wchar_t* channel = L"Security",
                                       const wchar_t* xpath = nullptr) {
    PollResult result;
    if (max_events < 1) max_events = 1;
    if (max_events > kLogBatchMaxRecords) max_events = kLogBatchMaxRecords;
    if (!xpath) {
        // Keep in lock-step with kWindowsAuthXPath in log_batch.h.
        xpath = L"Event/System[EventID=4624 or EventID=4625 or EventID=4634 or "
                L"EventID=4648 or EventID=4672 or EventID=4740]";
    }

    const bool have_bookmark = !load_text_file(bookmark_path).empty();
    if (!have_bookmark) {
        result.baseline = true;
        result.bookmark_xml = baseline_bookmark(channel, xpath);
        result.ok = true;
        return result;
    }

    EVT_HANDLE hBookmark = create_bookmark_from_file(bookmark_path);
    if (!hBookmark) {
        result.ok = false;
        return result;
    }

    EVT_HANDLE hResults = EvtQuery(nullptr, channel, xpath,
        EvtQueryChannelPath | EvtQueryForwardDirection);
    if (!hResults) {
        EvtClose(hBookmark);
        result.ok = false;
        return result;
    }

    // Position just after the bookmarked event. If the bookmark is stale
    // (channel wrapped / cleared), re-baseline rather than dumping history.
    if (!EvtSeek(hResults, 1, hBookmark, 0,
                 EvtSeekRelativeToBookmark | EvtSeekStrict)) {
        EvtClose(hResults);
        EvtClose(hBookmark);
        result.baseline = true;
        result.bookmark_xml = baseline_bookmark(channel, xpath);
        return result;
    }

    while (static_cast<int>(result.events_xml.size()) < max_events) {
        DWORD want = static_cast<DWORD>(
            max_events - static_cast<int>(result.events_xml.size()));
        if (want > 8) want = 8;
        EVT_HANDLE evts[8] = {};
        DWORD returned = 0;
        if (!EvtNext(hResults, want, evts, 2000, 0, &returned) || returned == 0) {
            // ERROR_NO_MORE_ITEMS is the normal end of the channel.
            break;
        }
        for (DWORD i = 0; i < returned; ++i) {
            std::string xml = render_xml(evts[i], EvtRenderEventXml);
            if (!xml.empty()) result.events_xml.push_back(std::move(xml));
            EvtUpdateBookmark(hBookmark, evts[i]);
            EvtClose(evts[i]);
        }
    }

    result.bookmark_xml = render_xml(hBookmark, EvtRenderBookmark);
    EvtClose(hResults);
    EvtClose(hBookmark);
    return result;
}

inline bool persist_bookmark(const std::string& path, const std::string& xml) {
    if (xml.empty() || path.empty()) return false;
    return save_text_file(path, xml);
}

} // namespace win_event_log

#endif // _WIN32
#endif
