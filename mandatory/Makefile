NAME = ft_malcolm
CC = cc
CFLAGS = -Werror -Wall -Wextra
RM = rm -rf

SRC = main.c \
	utils.c \
	printing.c \
	parsing.c \
	create_frame.c \
	process_frame.c \

OBJ = $(SRC:.c=.o)

all : $(NAME)

$(NAME): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(NAME)

clean:
	$(RM) $(OBJ)

fclean: clean
	$(RM) $(NAME)

re: fclean all

start:
	docker compose up -d --build

stop:
	docker compose down

clean-D:
	docker rmi $$(docker images -a -q)
	docker system prune -f

PHONY: all clean fclean re start stop clean-D