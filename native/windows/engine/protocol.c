#include "engine.h"
#include <stdio.h>
#include <string.h>

static int label_char(unsigned char ch) {
    return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
           (ch >= '0' && ch <= '9') || strchr("_.:+/() -", ch) != NULL;
}

enum ao_result ao_parse_reply(const char *reply, size_t length, char name[201]) {
    size_t i, size;
    name[0] = 0;
    if (!reply || length >= AO_REPLY_LIMIT || memchr(reply, 0, length)) return AO_UNKNOWN;
    if (length == 10 && !memcmp(reply, "stream: OK", 10)) return AO_CLEAR;
    if (length < 15 || memcmp(reply, "stream: ", 8) ||
        memcmp(reply + length - 6, " FOUND", 6)) return AO_UNKNOWN;
    size = length - 14;
    if (!size || size > 200 || reply[8] == ' ' || reply[8 + size - 1] == ' ') return AO_UNKNOWN;
    for (i = 0; i < size; ++i) if (!label_char((unsigned char)reply[8 + i])) return AO_UNKNOWN;
    memcpy(name, reply + 8, size);
    name[size] = 0;
    return !strncmp(name, "Heuristics.", 11) || !strncmp(name, "PUA.", 4) ? AO_REVIEW : AO_THREAT;
}

int ao_database_current(const char *version, time_t now) {
    char engine[100], generation[16], weekday[4], month[4];
    const char *months[] = {"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};
    int day, hour, minute, second, year, consumed = 0, month_index;
    struct tm date = {0};
    time_t published;
    double age;
    if (!version || sscanf(version, "ClamAV %99[^/]/%15[0-9]/%3s %3s %2d %2d:%2d:%2d %4d%n",
        engine, generation, weekday, month, &day, &hour, &minute, &second, &year, &consumed) != 9 ||
        version[consumed] || year < 1970 || year > 2100 || day < 1 || day > 31 ||
        hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 59) return 0;
    for (month_index = 0; month_index < 12; ++month_index) if (!strcmp(month, months[month_index])) break;
    if (month_index == 12) return 0;
    date.tm_year = year - 1900; date.tm_mon = month_index; date.tm_mday = day;
    date.tm_hour = hour; date.tm_min = minute; date.tm_sec = second; date.tm_isdst = -1;
    published = mktime(&date);
    if (published == (time_t)-1 || date.tm_year != year - 1900 || date.tm_mon != month_index ||
        date.tm_mday != day || date.tm_hour != hour || date.tm_min != minute || date.tm_sec != second) return 0;
    age = difftime(now, published);
    return age >= -86400 && age <= 7 * 86400;
}


uint64_t ao_database_generation(const char *version) {
    const char *first, *last, *cursor;
    uint64_t value = 0;
    if (!version || strncmp(version, "ClamAV ", 7)) return 0;
    first = strchr(version + 7, '/');
    if (!first) return 0;
    last = strchr(first + 1, '/');
    if (!last || last == first + 1 || (size_t)(last - first - 1) > 15) return 0;
    for (cursor = first + 1; cursor < last; ++cursor) {
        unsigned digit;
        if (*cursor < '0' || *cursor > '9') return 0;
        digit = (unsigned)(*cursor - '0');
        if (value > ((uint64_t)INT64_MAX - digit) / 10) return 0;
        value = value * 10 + digit;
    }
    return value;
}
