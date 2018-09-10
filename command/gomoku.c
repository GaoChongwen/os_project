#include"stdio.h"


char board[30][30];
int cnt = 0;    //number of chess pices has been put
char pieces[2] = {'X', 'O'};    //player 1, 2's chess

int dxx[8] = {-1,0,-1,-1,1,1,0,1};
int dyy[8] = {0,-1,-1,1,-1,1,1,0};

void init(){
    cnt = 0;
    for(int i = 1; i <= 15; i++)
        for(int j = 1; j <= 15; j++)
            board[i][j] = '*';
}

void printBoard(){
    int i,j;
    for(i = 1; i <= 15; i ++){
        for(j = 1; j <= 15; j++){
            
            printf("%c ", board[i][j]);
        }
        printf("\n");
    }
}

int check(int x, int y){
    if(x < 1||x > 15||y < 1||y > 15){
        return 0;
    }
    return 1;
}

int checkInput(int x, int y){
    if(board[x][y] != '*' || (!check(x, y))){
        return 0;
    }
    return 1;
}

int checkWinner(int num, int x, int y){
    if(cnt == 15 * 15)
        return 1;
    //check four directions
    for(int i = 0; i < 4; i++){
        int sum = 1;
        int xx = x + dxx[i];
        int yy = y + dyy[i];
        while(board[xx][yy] == pieces[num] && check(xx,yy) == 1){
            sum++;
            xx = xx+dxx[i];
            yy = yy+dyy[i];
        }
        xx = x + dxx[7-i];
        yy = y + dyy[7-i];
        while(board[xx][yy] == pieces[num] && check(xx,yy) == 1){
            sum++;
            xx = xx+dxx[7-i];
            yy = yy+dyy[7-i];
        }
        if(sum >= 5)
            return 1;
    }
    return 0;
}

int charToInt(char c){
	return (c - '0');
}

void run(){
	char xy[6];
    int x, y;
    int ifPut = 0;
    init();
    int num = 0;    //player number
    while(1){
        printBoard();
        printf("\n");
        printf("player %d please input the location of your chess piece, just like '01 01':", num + 1);
        
        while(1){
            read(0, xy, 6);
            if (xy[0] == 'q'){
            	return;
            }
            if (xy[0] == 'h'){
            	// printf("%s\n", xy);
            	GomokuHelp();
            	break;
            }
            x = charToInt(xy[0]) * 10 + charToInt(xy[1]);
            y = charToInt(xy[3]) * 10 + charToInt(xy[4]);
            if(checkInput(x,y) == 1){
                ifPut = 1;
                break;
            }
            printf("Locatin illegal, please input again: \n");
        }
        if (ifPut == 1){
        	board[x][y] = pieces[num];
            cnt++;
            ifPut = 0;
        }
        if(checkWinner(num,x,y) == 1){
            printf("%d player win! \n", num + 1);
            return;
        }
      
        num = 1 - num;
    }
}

void GomokuHelp(){
	printf("***********************************************\n");
    printf("*  1. Enter 1-15 row number                   *\n");
    printf("*  2. Enter 1-15 col number                   *\n");
    printf("*  3. Player 1 hold 'X' and Palyer 2 hold 'O' *\n");
    printf("*  4. Enter q to quit                         *\n");
    printf("*  5. Enter h to show help menu               *\n");
    printf("***********************************************\n");
}

int main(){
    printf("***********************************************\n");
    printf("*                    GOMOKU                   *\n");
    printf("***********************************************\n");
    
    GomokuHelp();
    printf("please put your chess pieces within 15 checker!\n");
    run();

    printf("GAME OVER!\n");
    printf("\n");
    return 0;
}

