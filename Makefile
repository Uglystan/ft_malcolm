NAME = ft_malcolm
CC = cc
CFLAGS = -Werror -Wall -Wextra
RM = rm -rf

SRC = main.c \

OBJ = $(SRC:.c=.o)

all : $(NAME)

$(NAME): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(NAME)

clean:
	$(RM) $(OBJ)

fclean: clean
	$(RM) $(NAME)

re: fclean all

PHONY: all clean fclean re