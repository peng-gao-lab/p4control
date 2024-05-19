%{
#include <cstdio>
#include <iostream>
#include <cassert>
#include <vector>
#include <string>
#include <regex>
#include <unistd.h>
#include <chrono>
#include <iostream>
#include <fstream>
using namespace std::chrono;
using namespace std;

string label;
string src_ip_address;
string dst_ip_address;
string decision;

bool is_ip_address(string s) {
  std::regex r ("\"[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}\"");
  if (regex_match(s, r)) {
    cout << "Detected an IP address " + s << endl;
    return true;
  } else {
    cout << s + " is not an IP address!" << endl;
    return false;
  }
}

using namespace std;


extern "C" int yylex();
extern "C" int yyparse();
extern "C" FILE *yyin;

void yyerror(const char *s);
%}


// use that union instead of "int" for the definition of "yystype":
%union {
	int ival;
	float fval;
	char *sval;
	int listval[100];
}

%token IF THEN
%token MATCH

// actions
%token DROP FWD MODIFYTTL REROUTE

// delineators
%token LP RP

// operators
%token EQ CONTAINS
%token AND
%token ALICE BOB SALES DEV

// base types
%token <ival> CONST
%token <sval> VAR
%token <sval> IP

%%
netcl:
	statements {
                 cout << "\nFile ready" << endl;
               }
	;
statements:
	statement
	;

matchexpr:
	MATCH LP binaryexpr RP  {
                              cout << "matchexpr" << endl;
                            }
	;

statement:
	IF matchexpr THEN action {
                               cout << "statement: matchexpr " << endl;
                             }
	;

action:
     DROP { decision = "1"; cout << "Action: DROP" << endl;}
	| FWD { decision = "0"; cout << "Action: FWD" << endl;}
  | MODIFYTTL { decision = "2"; cout << "Action: MODIFYTTL" << endl;}
  | REROUTE { decision = "3"; cout << "Action: REROUTE" << endl;}
	
;

binaryexpr:

  VAR binaryop VAR boolop VAR binaryop IP {
                         label = $3;
                         dst_ip_address = $7;
                         cout << "binary expr" << endl;
  }
	;

binaryop:
	   CONTAINS {cout << "contains" << endl;}
    | EQ {cout << "==" << endl;}
	;

boolop:
	AND
	;
%%

static void usage()
{
   fprintf(stderr, "To complie NetCL rules: ./netcl-compile -i <netcl_rules> -o <output_file>\n");
}

// helper function: find+replace string in a string
void ReplaceStringInPlace(std::string& subject, const std::string& search,
                          const std::string& replace)
{
    size_t pos = 0;
    while ((pos = subject.find(search, pos)) != std::string::npos) {
         subject.replace(pos, search.length(), replace);
         pos += replace.length();
    }
}

int generate_policy(string file_name)
{
   ofstream policy(file_name);
   int ret;
   string rule_output;

   ifstream f("./templates/table_2_template.py");
   string original_template((std::istreambuf_iterator<char>(f)),
                 (std::istreambuf_iterator<char>()));
   rule_output = original_template;
   /* ReplaceStringInPlace(rule_output, "SRC_IP", check->src_ip); */
   ReplaceStringInPlace(rule_output, "LABEL", label);
   ReplaceStringInPlace(rule_output, "DST_IP", dst_ip_address);
   ReplaceStringInPlace(rule_output, "DEC", decision);
   policy << rule_output << endl;
   rule_output = "";
   cout << "finish generate" << endl;
   return 0;
}

int main(int argc, char *argv[]) {
   int opt;
   char *policy_file = NULL;
   char *output_file = NULL;

   // parse arguments
   while ((opt = getopt(argc, argv, "i:o:")) != -1) {
      switch (opt) {
         case 'i':
            policy_file = optarg;
            break;
         case 'o':
            output_file = optarg;
            break;
         default:
            usage();
            exit(1);
      }
   }

   if (policy_file == NULL || output_file == NULL) {
      usage();
      exit(1);
   }

	// open the policy file
	FILE *fp = fopen(policy_file, "r");
   if (fp == NULL) {
      fprintf(stderr, "failed to open policy file %s", policy_file);
      return 1;
   }

	// set flex to read from it instead of defaulting to STDIN:
	yyin = fp;

	// parse through the input until there is no more:
	do {
		yyparse();
	} while (!feof(yyin));

   //Pushing soon compiling multiple policies and multiple table templates
   generate_policy(output_file);
   
   return 0;
}



void yyerror(const char *s)
{
	cout << "Parse error!  Message: " << s << endl;
	exit(-1);
}
