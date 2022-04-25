# include <display.h>

void showtime() {
    INITCOLOR(RED_COLOR);
    printf("[%s] ", __DATE__);
    INITCOLOR(GREEN_COLOR);
    printf("[%s] ", __TIME__);
    INITCOLOR(ZERO_COLOR);
}