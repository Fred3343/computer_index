#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <jansson.h>

int ensure_dir(const char* path)
{
    struct stat st; if (stat(path, &st) == 0)
    {
        if (S_ISDIR(st.st_mode)) return 0; errno = ENOTDIR; return -1;
    }
    return mkdir(path, 0755);
}

int json_save_pretty(json_t* obj, const char* path)
{
    return json_dump_file(obj, path, JSON_INDENT(2));
}
