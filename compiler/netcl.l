%{
#include <cstdio>
#include <iostream>
#include <vector>
#include <string>
#include<stdio.h>
#include<string.h>

using namespace std;
#define YY_DECL extern "C" int yylex()

#include "netcl.tab.h" 
// support tags 0-Alice 1-Bob 2-Sales 3-Dev
%}
%%
"//".*      {/* comment */ }
if			{ return IF; }
then			{ return THEN; }
drop			{ return DROP; }
alice			{ return ALICE; }
bob			{ return BOB; }
sales			{ return SALES; }
dev			{ return DEV; }
modify		{ return MODIFYTTL; }
fwd				{ return FWD; }
reroute		{ return REROUTE; }
match			{ return MATCH; }
contains			{ return CONTAINS; }
"("			{ return LP; }
")"			{ return RP; }
"=="			{ return EQ; }
"&&"			{ return AND; }
[ \t\n]           	;
"\""[0-9.]+"\"" { yylval.sval = strdup(yytext); return IP; }
[0-9]+            	{ yylval.ival = atoi(yytext); return CONST; }
[a-zA-Z0-9]+      	{
				yylval.sval = strdup(yytext);
				return VAR;
			}
.           		;
%%
