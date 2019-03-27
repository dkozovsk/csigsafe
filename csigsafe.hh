#include <iostream>
#include <list>
#include <set>

#include "gcc-plugin.h"
#include "plugin-version.h"

#include "cp/cp-tree.h"
#include "context.h"
#include "gimple.h"
#include "gimple-predict.h"
#include "tree-pass.h"
#include "tree-ssa-operands.h"
#include "gimple-iterator.h"
#include "tree-pretty-print.h"
#include "gimple-pretty-print.h"


#define RC_NOT_ASYNCH_SAFE 0
#define RC_ASYNCH_SAFE     1
#define RC_ERRNO_CHANGED   2
#define RC_SAFE_EXIT       4
#define RC_ERRNO_SETTER    8
#define RC_ASYNCH_UNSAFE   -1
#define RC_CYCLIC          110

#define FLG_SCANED 0
#define FLG_IS_HANDLER 1
#define FLG_IS_OK 2 
#define FLG_NOT_SAFE 3
#define FLG_WAS_ERR 4
#define FLG_FATAL 5
#define FLG_IS_EXIT 6
#define FLG_CAN_BE_SETTER 7
#define FLG_IS_ERRNO_SETTER 8
#define FLG_ERRNO_CHANGED 9
#define FLG_OUT_OF_RANGE 10	//this is invalid index, used in control of range

enum instruction_code {
	IC_CHANGE_ERRNO,
	IC_SAVE_ERRNO,
	IC_SAVE_FROM_VAR,
	IC_DESTROY_STORAGE,
	IC_RESTORE_ERRNO,
	IC_SET_FROM_PARM,
	IC_EXIT,
	IC_DEPEND
};

struct instruction {
	instruction_code ic;
	tree var=nullptr;
	tree from_var=nullptr;
	unsigned int param_pos=0;
	location_t instr_loc;
};

// struct for remembering dependencies across functions
struct depend_data {
  tree fnc;
  location_t loc;
  gimple * stmt;
  unsigned int parent_block_id;
  unsigned int parent_instr_loc;
  bool cyclic=false;
};

//struct for remembering assigned functions to sigaction struct variables
struct handler_in_var {
	 const char* var_name;
	 tree handler;
};

struct setter_function {
	 const char* setter;
	 unsigned int position;
};

struct remember_error {
	location_t err_loc;
	tree err_fnc;
	bool err_fatal=false;
};

struct errno_var {
	unsigned int id;
	const char *name;
};

//TODO better name
struct errno_in_builtin {
	tree var=nullptr;
	unsigned int id;
	bool valid=false;
};

class function_data;

class bb_data {
	unsigned int block_id;
public:
	bool computed=false;
	bool is_exit=false;
	std::list<instruction> instr_list;
	std::set<errno_var> input_set;
	std::set<errno_var> output_set;
	std::list<unsigned int> preds;
	
	//constructor
	bb_data(unsigned int id);
	bb_data() = delete;
	//methods
	bool compute(location_t &err_loc, tree &err_fnc, bool &changed, function_data &obj);
	unsigned int get_block_id();
};

//struct for storing all informations about scaned functions
class function_data {
	bool flags[10];
	function* fnc_ptr;
	tree fnc_decl;
public:
	std::list<remember_error> err_log;
	std::list<depend_data> depends;
	
	location_t errno_loc;
	tree errno_fnc;
	std::list<tree> stored_errno;
	
	std::list<bb_data> block_status;
	//constructor
	function_data(function* fun, tree fnc_tree);
	function_data() = delete;
	//methods
	void set_flag(unsigned int index,bool value);
	bool get_flag(unsigned int index);
	tree get_fnc_decl();
	function* get_fnc_ptr();
	void process_gimple_call(bb_data &status,gimple * stmt, bool &all_ok, std::list<const char*> &call_tree,
									bool &errno_valid, unsigned int &errno_stored, std::list<tree> &errno_ptr);
	void process_gimple_assign(bb_data &status, gimple * stmt, bool &errno_valid, unsigned int &errno_stored,
										errno_in_builtin &errno_builtin_storage, std::list<tree> &errno_ptr);
	void analyze_CFG();
};

class plugin_data {
public:
	std::list<function_data> fnc_list;
	std::list<tree> handlers;
	std::list<handler_in_var> possible_handlers;
	std::list<setter_function> own_setters;
	std::list<setter_function> errno_setters;

	bool dependencies_handled=true;
	bool added_new_setter=false;
	
	//methods
	void handle_dependencies();
	//errno setter list
	bool has_same_param(setter_function &setter);
	void remove_errno_setter(setter_function &setter);
	//handler setter list
	tree scan_own_handler_setter(gimple* stmt, tree fun_decl);
};

int8_t is_handler_ok_fnc (const char* name);
bool is_handler_wrong_fnc(const char* name);
int8_t scan_own_function (const char* name, std::list<const char*> &call_tree, bool *handler_found);
tree get_var_from_setter_stmt (gimple* stmt);
tree give_me_handler(tree var,bool first);
//setter list
bool is_setter(tree fnc, std::list<setter_function> &setter_list);
//CFG analisys
void intersection(std::set<errno_var> &destination, std::set<errno_var> &source);
bool equal_sets(std::set<errno_var> &a, std::set<errno_var> &b);
errno_var tree_to_errno_var(tree var);
//warnings
inline void print_warning(tree handler, tree fnc,location_t loc,bool fatal);
void print_note(tree fnc, location_t loc, bool fatal);
inline void print_errno_warning(tree handler, tree fnc, location_t loc);
void print_errno_note(tree fnc);
//errno list operations
bool is_var_in_list(tree var, std::list<tree> &list);
void add_unique_to_list(tree var, std::list<tree> &list);
//bool operators for errno_var
bool operator<(const errno_var &a, const errno_var &b);
bool operator==(const errno_var &a, const errno_var &b);


