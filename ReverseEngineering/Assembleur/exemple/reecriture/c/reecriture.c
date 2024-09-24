// on veut recoder strlen en assembleur. 
// pour ca on le fait en c, et on passe ca en reverse engineering

int main (){
    char *str = "Hello World!";
    int len = 0;
    while (str[len] != '\0'){
        len++;
    }
    return len;
}