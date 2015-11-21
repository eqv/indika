unsigned int strlength(char* str){
  unsigned int len = 0;
  while(*str){
    str++;
    len++;
  }
  return len;
}

void str_reverse(char* str){
  char* other = str + strlength(str);
  while(*str){
    *str = *other;
    str++;
    other--;
  }
}

void str_id(char* str){
  char* other = str + strlength(str);
  while(str < other){
    *str = *str;
    str++;
  }
}

int main(int argc, char *argv[])
{
  str_reverse("foo"); //crashes, but makes sure the functions are included
  str_id("foo");
	return 0;
}
