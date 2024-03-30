#include <unistd.h>

size_t ft_strlen(const char *str)
{
    size_t i = 0;
    for(; str[i] != '\0'; i++)
    {
    }
    return (i);
}

void ft_strcpy(char *dest, const char *src)
{
    size_t i = 0;
    for (; i < ft_strlen(src); i++)
    {
        dest[i] = src[i];
    }
    dest[i] = '\0';
}