#include "csigsafe.hh"

static plugin_data data;

static const char * const plugin_name = "csigsafe";
static const char * const release_version = "1.00";

//this variable represents errno in the analysis
static const errno_var pseudo_errno={
	.id=0,
	.name=nullptr
};

//bool operators for comparing errno_var
//others bool operators can be substituted using this two and negation
//most necessary are == and !=(substituted as negation of ==)
//operator < is used in sets for ordering
bool operator< (const errno_var &a, const errno_var &b)
{
	if (!a.name)
		return b.name != nullptr;
	else if(!b.name)
		return false;
	if (a.id==b.id)
		return strcmp(a.name,b.name) < 0;
	return a.id < b.id;
}
bool operator== (const errno_var &a, const errno_var &b)
{
	if (!a.name || !b.name)
		return b.name == a.name; //errno has no name, id is not important
	if (a.id==b.id)
		return strcmp(a.name,b.name) == 0;
	return false;
}

bb_data::bb_data(unsigned int id)
{
	this->block_id=id;
}

unsigned int bb_data::get_block_id()
{
	return this->block_id;
}

void function_data::set_flag(unsigned int index,bool value)
{
	if(index>=FLG_OUT_OF_RANGE)
		return;
	this->flags[index]=value;
}
bool function_data::get_flag(unsigned int index)
{
	if(index>=FLG_OUT_OF_RANGE)
		return false;
	return this->flags[index];
}
function_data::function_data(function* fun, tree fnc_tree)
{
	this->fnc_ptr=fun;
	this->fnc_decl=fnc_tree;
	
	this->set_flag(FLG_SCANED,false);
	this->set_flag(FLG_IS_HANDLER,false);
	this->set_flag(FLG_IS_OK,false);
	this->set_flag(FLG_NOT_SAFE,false);
	this->set_flag(FLG_WAS_ERR,false);
	this->set_flag(FLG_FATAL,false);
	this->set_flag(FLG_IS_EXIT,false);
	this->set_flag(FLG_CAN_BE_SETTER,true);
	this->set_flag(FLG_IS_ERRNO_SETTER,false);
	this->set_flag(FLG_ERRNO_CHANGED,false);
}
tree function_data::get_fnc_decl()
{
	return this->fnc_decl;
}
function* function_data::get_fnc_ptr()
{
	return this->fnc_ptr;
}

//scan functions which are defined after the scan of function, which called them
void plugin_data::handle_dependencies()
{
	bool all_solved=true;
	bool nothing_solved=false;
	while(!nothing_solved)
	{
		nothing_solved=true;
		all_solved=true;
		for (function_data &obj: this->fnc_list)
		{
			bool solved=true;
			if (obj.get_flag(FLG_IS_OK))
				continue;
			if (obj.depends.empty())
				solved=false;
			while(solved && !obj.depends.empty())
			{
				std::list<depend_data>::iterator depend_it;
				for(depend_it=obj.depends.begin();depend_it!=obj.depends.end();)
				{
					depend_data depends=*depend_it;
					std::list<const char*> call_tree;
					int8_t return_number=scan_own_function(get_name(depends.fnc),call_tree,nullptr);
					if (return_number < 99)
					{
						//if call of this function may change errno or is exit function replace placeholder with corresponding instruction
						if ((return_number == RC_ERRNO_CHANGED || return_number == RC_SAFE_EXIT || return_number == RC_ERRNO_SETTER) && !obj.get_flag(FLG_WAS_ERR))
						{
							for (bb_data &block_data : obj.block_status)
							{
								if(depends.parent_block_id==block_data.get_block_id())
								{
									if(block_data.instr_list.empty())
										break;
									std::list<instruction>::iterator it=block_data.instr_list.begin();
									for(unsigned int i = 1; i < depends.parent_instr_loc;i++)
									{
										if(it==block_data.instr_list.end())
											break;
										++it;
									}
									if (return_number == RC_ERRNO_SETTER)
									{
										if((it->var=get_var_from_setter_stmt (depends.stmt)))
											it->ic=IC_RESTORE_ERRNO;
									}
									else
										it->ic=return_number == RC_ERRNO_CHANGED ? IC_CHANGE_ERRNO : IC_EXIT;
									if(!block_data.is_exit)
										block_data.is_exit=return_number == RC_SAFE_EXIT;
									block_data.computed=false;
									break;
								}
							}
						}
						else if (return_number == RC_NOT_ASYNCH_SAFE || return_number == RC_ASYNCH_UNSAFE)
						{
							obj.set_flag(FLG_NOT_SAFE,true);
							if (!obj.get_flag(FLG_FATAL))
								obj.set_flag(FLG_FATAL,return_number==RC_ASYNCH_UNSAFE);
							if (obj.get_flag(FLG_IS_HANDLER))
								print_warning(obj.get_fnc_decl(),depends.fnc,depends.loc,return_number==RC_ASYNCH_UNSAFE);
							else
							{
								remember_error new_err;
								new_err.err_loc = depends.loc;
								new_err.err_fnc = depends.fnc;
								new_err.err_fatal = return_number==RC_ASYNCH_UNSAFE;
								obj.err_log.push_back(new_err);
							}
						}
						std::list<depend_data>::iterator tmp=depend_it;
						++depend_it;
						obj.depends.erase(tmp);
						
					}
					else
					{
						if (return_number==RC_CYCLIC)
							depend_it->cyclic=true;
						++depend_it;
						solved=false;
						all_solved=false;
					}
				}
			}
			bool all_cyclic=true;
			for (depend_data &depends: obj.depends)
			{
				if(!depends.cyclic)
					all_cyclic=false;
			}
			//this fixes the problem in safe cyclic dependencies, which otherwise prevents start of the CFG analysis
			if(!obj.get_flag(FLG_WAS_ERR) && !obj.depends.empty() && obj.get_flag(FLG_IS_HANDLER) && all_cyclic)
			{
				if(obj.get_flag(FLG_SCANED))
				{
					obj.analyze_CFG();
					if (obj.get_flag(FLG_ERRNO_CHANGED) && obj.get_flag(FLG_IS_HANDLER))
					{
						solved=true;
						obj.set_flag(FLG_WAS_ERR,true);
						print_errno_warning(obj.get_fnc_decl(),obj.errno_loc);
					}
				}
			}
			else 
			{
				if(solved && obj.get_flag(FLG_SCANED))
				{
					obj.analyze_CFG();
					if (obj.get_flag(FLG_ERRNO_CHANGED) && obj.get_flag(FLG_IS_HANDLER))
					{
						obj.set_flag(FLG_WAS_ERR,true);
						print_errno_warning(obj.get_fnc_decl(),obj.errno_loc);
					}
				}
			}
			if (obj.get_flag(FLG_SCANED) && obj.depends.empty() && !obj.get_flag(FLG_NOT_SAFE))
				obj.set_flag(FLG_IS_OK,true);
			if (solved)
				nothing_solved=false;
		}
	}
	if (all_solved)
		this->dependencies_handled=true;
}

//add to list only if variable is not already in the list
void add_unique_to_list(tree var, std::list<tree> &list)
{
	if (!is_var_in_list(var,list))
		list.push_back(var);
}

//returns true if variable var is already located in the list
bool is_var_in_list(tree var, std::list<tree> &list)
{
	for(tree list_var : list)
	{
		if(DECL_UID (list_var)==DECL_UID (var))
		{
			const char* list_var_name=get_name(list_var);
			const char* var_name=get_name(var);
			if(!list_var_name || !var_name)
				continue;
			if(strcmp(list_var_name,var_name)==0)
				return true;
		}
	}
	return false;
}

//intersection of two sets to destination set(source set is unchanged)
void intersection(std::set<errno_var> &destination,std::set<errno_var> &source)
{
	std::set<errno_var>::iterator it=destination.begin();
	while(it!=destination.end())
	{
		std::set<errno_var>::iterator actual=it;
		++it;
		if(source.find(*actual)==source.end())
		{
			destination.erase(actual);
		}
	}
	it=destination.find(pseudo_errno);
	if(it!=destination.end())
	{
		std::set<errno_var>::iterator it_source=source.find(pseudo_errno);
		if(it_source!=source.end())
		{
			if(it->id!=it_source->id)
			{
				destination.erase(it);
				destination.insert(pseudo_errno);
			}
		}
	}
}

//returns true if two sets are equal
bool equal_sets(std::set<errno_var> &a,std::set<errno_var> &b)
{
	std::set<errno_var>::iterator it_a=a.begin();
	std::set<errno_var>::iterator it_b=b.begin();
	//because sets are ordered, it is possible to compare
	//first member with first, second with second and so on
	while(it_a != a.end() && it_b != b.end())
	{
		if (*it_a == pseudo_errno)
		{
			if(it_a->id != it_b->id)
				break;
		}
		if(!(*it_a == *it_b))
			break;
		++it_a;
		++it_b;
	}
	//sets should contain same amount of members
	if(it_a != a.end() || it_b != b.end())
		return false;
	return true;
}

//returns errno_var type variable from tree type variable
errno_var tree_to_errno_var(tree var)
{
	errno_var new_var;
	new_var.id=DECL_UID (var);
	new_var.name=get_name(var);
	if (!new_var.name)
		return pseudo_errno;
	return new_var;
}

//compute output set from input set for one basic block
//returns true, if errno is changed and computed block is return from the function, false otherwise
bool bb_data::compute(location_t &err_loc,bool &changed,function_data &obj)
{
	this->computed=true;
	std::set<errno_var> new_set=this->input_set;
	for (instruction &instr : this->instr_list)
	{
		switch (instr.ic)
		{
			case IC_CHANGE_ERRNO:
				{
					std::set<errno_var>::iterator it;
					it = new_set.find(pseudo_errno);
					if (it!=new_set.end())
					{
						err_loc=instr.instr_loc;
						new_set.erase(it);
					}
				}
				break;
			case IC_SAVE_ERRNO:
				{
					std::set<errno_var>::iterator it;
					it = new_set.find(pseudo_errno);
					if (it!=new_set.end())
					{
						errno_var new_var=tree_to_errno_var(instr.var);
						new_set.insert(new_var);
					}
				}
				break;
			case IC_SAVE_FROM_VAR:
				{
					std::set<errno_var>::iterator it;
					errno_var var=tree_to_errno_var(instr.from_var);
					if (var==pseudo_errno)
						break;
					it = new_set.find(var);
					if (it!=new_set.end())
					{
						errno_var new_var=tree_to_errno_var(instr.var);
						if (new_var==pseudo_errno)
							break;
						new_set.insert(new_var);
					}
				}
				break;
			case IC_DESTROY_STORAGE:
				{
					std::set<errno_var>::iterator it;
					it = new_set.find(tree_to_errno_var(instr.var));
					if (it!=new_set.end())
					{
						if(!(*it==pseudo_errno))
							new_set.erase(it);
					}
				}
				break;
			case IC_RESTORE_ERRNO:
				{
					std::set<errno_var>::iterator it;
					it = new_set.find(tree_to_errno_var(instr.var));
					if (it!=new_set.end())
					{
						new_set.insert(pseudo_errno);
					}
					else
					{
						std::set<errno_var>::iterator it;
						it = new_set.find(pseudo_errno);
						if (it!=new_set.end())
						{
							err_loc=instr.instr_loc;
							new_set.erase(it);
						}
					}
				}
				break;
			case IC_SET_FROM_PARM:
				{
					errno_var new_var;
					new_var.name=nullptr;
					new_var.id=instr.param_pos+1;
					std::set<errno_var>::iterator it;
					it = new_set.find(pseudo_errno);
					if (it!=new_set.end())
					{
						new_set.erase(it);
					}
					new_set.insert(new_var);
					break;
				}
			case IC_EXIT:
				return false;
				break;
			case IC_DEPEND:
				//this is only placeholder, may change later
				break;
			default:
				//this should never happen
				break;
		}
	}
	if(this->block_id==1)
	{
		std::set<errno_var>::iterator it;
		it = new_set.find(pseudo_errno);
		if (it==new_set.end())
		{
			return true;
		}
		if(it->id!=0 && obj.get_flag(FLG_CAN_BE_SETTER))
		{
			obj.set_flag(FLG_IS_ERRNO_SETTER,true);
			setter_function new_setter;
			new_setter.setter=get_name(obj.get_fnc_decl());
			new_setter.position=it->id-1;
			if (!is_setter(obj.get_fnc_decl(), data.errno_setters))
				data.errno_setters.push_back(new_setter);
			else
			{
				if(!data.has_same_param(new_setter))
				{
					obj.set_flag(FLG_CAN_BE_SETTER,false);
					data.remove_errno_setter(new_setter);
				}
			}
		}
		else if (obj.get_flag(FLG_CAN_BE_SETTER))
		{
			setter_function new_setter;
			new_setter.setter=get_name(obj.get_fnc_decl());
			obj.set_flag(FLG_CAN_BE_SETTER,false);
			data.remove_errno_setter(new_setter);
		}
		return false;
	}
	if (!equal_sets(new_set,this->output_set))
	{
		this->output_set=new_set;
		changed=true;
	}
	return false;
}

//analyze CFG for one function
void function_data::analyze_CFG()
{
	//analyze if it is own exit function
	//that means that all predecessors of exit block must
	//contain some asynchronous-safe exit function
	this->set_flag(FLG_IS_EXIT,true);
	//TODO better check for exit, own exit functions without noreturn
	//(not common would mean that i call my exit, and after that i call something else. it is nonsense)
	for(bb_data &status : this->block_status)
	{
		if(status.get_block_id()==1)
		{
			for(unsigned int predecessor : status.preds)
			{
				for (bb_data &block_data : this->block_status)
				{
					if(predecessor==block_data.get_block_id())
					{
						if(!block_data.is_exit)
							this->set_flag(FLG_IS_EXIT,false);
					}
				}
			}
			break;
		}
	}
	if(this->get_flag(FLG_IS_EXIT))
		return;
	bool changed=false;
	location_t err_loc;
	do
	{
		changed=false;
		for (bb_data &status : this->block_status)
		{
			std::set<errno_var> new_set;
			bool empty=true;
			//compute input set for block as intersection of output sets
			//of all blocks that are predecessors for computed block
			for(unsigned int predecessor : status.preds)
			{
				for (bb_data &block_data : this->block_status)
				{
					if(predecessor==block_data.get_block_id())
					{
						if (block_data.is_exit)
						{
							break;
						}
						if(empty && block_data.computed)
						{
							empty=false;
							new_set=block_data.output_set;
						}
						else if (block_data.computed)
						{
							intersection(new_set,block_data.output_set);
						}
						break;
					}
				}
			}
			if(status.computed && equal_sets(new_set,status.input_set))
				continue;
			if (!empty)
				status.input_set=new_set;
			if (status.compute(err_loc,changed,*this))
			{
				this->errno_loc=err_loc;
				this->set_flag(FLG_ERRNO_CHANGED,true);
				return;
			}
		}
	} while(changed);
}

//returns true if fnc is already a setter
bool is_setter(tree fnc, std::list<setter_function> &setter_list)
{
	for (setter_function &obj: setter_list)
	{
		if (strcmp(obj.setter,get_name(fnc)) == 0)
		{
			return true;
		}
	}
	return false;
}

//one function cant set errno from two different parameters
bool plugin_data::has_same_param(setter_function &setter)
{
	for (setter_function &obj: this->errno_setters)
	{
		if (strcmp(obj.setter,setter.setter) == 0)
		{
			if (obj.position==setter.position)
				return true;
			return false;
		}
	}
	return false;
}

//remove setter from errno_setters list
void plugin_data::remove_errno_setter(setter_function &setter)
{
	std::list<setter_function>::iterator it;
	for(it = this->errno_setters.begin(); it != this->errno_setters.end(); ++it)
	{
		if (strcmp(it->setter,setter.setter) == 0)
		{
			this->errno_setters.erase(it);
			return;
		}
	}
}

//this function returns variable, which is assigned to errno in errno setter function
tree get_var_from_setter_stmt (gimple*stmt)
{
	if (gimple_code(stmt)==GIMPLE_CALL)
	{
		for (setter_function &obj: data.errno_setters)
		{
			tree current_fn = gimple_call_fn(stmt);
			if (!current_fn)
				return nullptr;
			const char* name = get_name(current_fn);
			if (!name)
				return nullptr;
			if (strcmp(name,obj.setter)==0)
			{
				tree var = gimple_call_arg (stmt, obj.position);
				if (!var)
					break;
				//std::cerr << get_tree_code_name (TREE_CODE (var)) << "\n";
				if (TREE_CODE (var) == ADDR_EXPR)
				{
					var = TREE_OPERAND (var, 0);
					if (!var || TREE_CODE (var) != VAR_DECL)
						break;
					return var;
				}
				break;
			}
		}
	}
	return nullptr;
}

//get tree of handler from call stmt
tree get_handler(gimple* stmt)
{
	tree current_fn = gimple_call_fn(stmt);
	if (!current_fn)
		return nullptr;
	const char* name = get_name(current_fn);
	if (!name)
		return nullptr;
	if (strcmp(name,"sigaction")==0)
	{
		tree var = gimple_call_arg (stmt, 1);
		const char* name = get_name(var);
		if (!name)
			return nullptr;
		std::list<handler_in_var>::iterator it;
		for(it = data.possible_handlers.begin(); it != data.possible_handlers.end(); ++it)
		{
			if (strcmp(it->var_name,name)==0)
			{
				handler_in_var var_handler = *it;
				data.possible_handlers.erase(it);
				if(!is_gimple_addressable (var_handler.handler) && TREE_CODE(var_handler.handler) == ADDR_EXPR)
					return var_handler.handler;
				else if (TREE_CODE(var_handler.handler) == PARM_DECL)
				{
					unsigned counter=0;
					for (tree argument = DECL_ARGUMENTS (current_function_decl) ; argument ; argument = TREE_CHAIN (argument))
					{
						if (strcmp(get_name(argument),get_name(var_handler.handler))==0)
						{
							setter_function new_setter;
							new_setter.setter = get_name(current_function_decl);
							new_setter.position = counter;
							data.own_setters.push_front(new_setter);
							data.added_new_setter=true;
							break;
						}
						++counter;
					}
				}
				return nullptr;
			}
		}
		if (TREE_CODE(var) == ADDR_EXPR)
		{
			tree vardecl = TREE_OPERAND (var, 0);
			if (!vardecl)
				return nullptr;
			if (TREE_CODE(vardecl)==VAR_DECL && !DECL_EXTERNAL (vardecl))
			{
				tree initial = DECL_INITIAL(vardecl);
				if (initial)
				{
					initial = give_me_handler(initial,true);
					if(!is_gimple_addressable (initial) && TREE_CODE(initial) == ADDR_EXPR)
						return initial;
				}
			}
		}
	}
	else if (strcmp(name,"signal")==0 || strcmp(name,"bsd_signal")==0 || strcmp(name,"sysv_signal")==0)
	{
		tree var = gimple_call_arg (stmt, 1);
		if(!is_gimple_addressable (var) && TREE_CODE(var) == ADDR_EXPR)
			return var;
		else if (TREE_CODE(var) == PARM_DECL)
		{
			unsigned counter=0;
			for (tree argument = DECL_ARGUMENTS (current_function_decl) ; argument ; argument = TREE_CHAIN (argument))
			{
				if (strcmp(get_name(argument),get_name(var))==0)
				{
					setter_function new_setter;
					new_setter.setter = get_name(current_function_decl);
					new_setter.position = counter;
					data.own_setters.push_front(new_setter);
					data.added_new_setter=true;
					break;
				}
				++counter;
			}
		}
	}
	else
		return data.scan_own_handler_setter(stmt,current_function_decl);
	return nullptr;
}

//look through own setters, try to find handler if own setter was called
tree plugin_data::scan_own_handler_setter(gimple* stmt,tree fun_decl)
{
	for (setter_function &obj: this->own_setters)
	{
		tree current_fn = gimple_call_fn(stmt);
		if (!current_fn)
			return nullptr;
		const char* name = get_name(current_fn);
		if (!name)
			return nullptr;
		if (strcmp(name,obj.setter)==0)
		{
			tree var = gimple_call_arg (stmt, obj.position);
			if(!is_gimple_addressable (var) && TREE_CODE(var) == ADDR_EXPR)
				return var;
			else if (TREE_CODE(var) == PARM_DECL)
			{
				unsigned counter=0;
				for (tree argument = DECL_ARGUMENTS (fun_decl) ; argument ; argument = TREE_CHAIN (argument))
				{
					if (strcmp(get_name(argument),get_name(var))==0)
					{
						if (is_setter(fun_decl,this->own_setters))
						{
							break;
						}
						setter_function new_setter;
						new_setter.setter = get_name(fun_decl);
						new_setter.position = counter;
						this->own_setters.push_front(new_setter);
						this->added_new_setter=true;
						break;
					}
					++counter;
				}
			}
		}
	}
	return nullptr;
}

//try to find signal handler in the initialization of variable
//first indicate if the function is called for the first time, second call is recursive
tree give_me_handler(tree var,bool first)
{
	//inspired from code in gimple-pretty-print.c
	if (TREE_CODE(var)==CONSTRUCTOR)
	{
		unsigned HOST_WIDE_INT ix;
		tree field, val;

		FOR_EACH_CONSTRUCTOR_ELT (CONSTRUCTOR_ELTS (var), ix, field, val)
		{
			if (field)
			{
				if(first && strcmp(get_name(field),"__sigaction_handler")==0)
				{
					if (val)
					{
						return give_me_handler(val,false);
					}
				}
				else if (!first && (strcmp(get_name(field),"sa_handler")==0 || strcmp(get_name(field),"sa_sigaction")==0))
				{
					return val;
				}
			}
		}
	}
	return nullptr;
}

//scan if the called function in signal handler is asynchronous-safe and if errno may be changed
//returns 0 when function is not asynchronous-safe,
//        1 if it is safe and errno is not changed,
//        2 if it is safe, but errno may be changed,
//        4 if it is safe exit function
//       -1 if it is asynchronous-unsafe
int8_t is_handler_ok_fnc (const char* name)
{
	if (!name)
		return RC_NOT_ASYNCH_SAFE;
	static const char* safe_fnc[]={
		"aio_error", "alarm", "cfgetispeed", "cfgetospeed", "getegid",
		"geteuid", "getgid", "getpgrp", "getpid", "getppid", "getuid",
		"posix_trace_event", "pthread_kill", "pthread_self",
		"pthread_sigmask", "raise", "sigfillset", "sleep", "umask"};
	static const char* change_errno_fnc[]={
		"accept", "access", "aio_return", "aio_suspend", "bind", "cfsetispeed", "cfsetospeed",
		"clock_gettime", "close", "connect", "creat", "dup", "dup2", "execl", "execle", "execv",
		"execve", "faccessat", "fcntl", "fdatasync", "fexecve", "fchdir", "fchmod", "fchmodat",
		"fchown", "fchownat", "fork", "fstat", "fstatat", "fsync", "ftruncate", "futimens",
		"getgroups", "getpeername", "getsockname", "getsockopt", "chdir", "chmod", "chown",
		"kill", "link", "linkat", "listen", "lseek", "lstat", "mkdir", "mkdirat", "mkfifo",
		"mkfifoat", "mknod", "mknodat", "open", "openat", "pause", "pipe", "poll", "pselect",
		"read", "readlink", "readlinkat", "recv", "recvfrom", "recvmsg", "rename", "renameat",
		"rmdir", "select", "sem_post", "send", "sendmsg", "sendto", "setgid", "setpgid", "setsid",
		"setsockopt", "setuid", "shutdown", "sigaction", "sigaddset", "sigdelset", "sigemptyset",
		"sigismember", "signal", "sigpause", "sigpending", "sigprocmask", "sigqueue", "sigset",
		"sigsuspend", "sockatmark", "socket", "socketpair", "stat", "symlink", "symlinkat", "tcdrain",
		"tcflow", "tcflush", "tcgetattr", "tcgetpgrp", "tcsendbreak", "tcsetattr", "tcsetpgrp", "time",
		"timer_getoverrun", "timer_gettime", "timer_settime", "times", "uname", "unlink", "unlinkat",
		"utime", "utimensat", "utimes", "wait", "waitpid", "write"};
	static const char* safe_exit_fnc[]={
		"abort", "_exit", "_Exit"};
	for(unsigned i=0;i<(sizeof(safe_exit_fnc)/sizeof(char*));++i)
	{
		if(strcmp(safe_exit_fnc[i],name)==0)
			return RC_SAFE_EXIT;
	}
	for(unsigned i=0;i<(sizeof(safe_fnc)/sizeof(char*));++i)
	{
		if(strcmp(safe_fnc[i],name)==0)
			return RC_ASYNCH_SAFE;
	}
	for(unsigned i=0;i<(sizeof(change_errno_fnc)/sizeof(char*));++i)
	{
		if(strcmp(change_errno_fnc[i],name)==0)
			return RC_ERRNO_CHANGED;
	}
	return is_handler_wrong_fnc(name) ? RC_ASYNCH_UNSAFE : RC_NOT_ASYNCH_SAFE;
}

//scan if the called function in signal handler is asynchronous-unsafe
bool is_handler_wrong_fnc(const char* name)
{
	if (!name)
		return false;
	static const char* unsafe_fnc[]={
		"aligned_alloc", "atexit", "__builtin_putchar", "__builtin_puts", "calloc",
		"err", "error", "error_at_line", "errx", "exit", "fclose", "fcloseall",
		"fgetc", "fgetc_unlocked", "fgetwc", "fgetwc_unlocked", "fopen", "fopen64",
		"fprintf", "fputc", "fputc_unlocked", "fputs", "fputs_unlocked", "fputwc",
		"fputwc_unlocked", "fputws", "fputws_unlocked", "free", "freopen",
		"freopen64", "fscanf", "fwprintf", "fwscanf", "getc", "getc_unlocked",
		"getchar", "getchar_unlocked", "getw", "getwc", "getwc_unlocked",
		"getwchar", "getwchar_unlocked", "grantpt", "longjmp", "mallinfo",
		"malloc", "mallopt", "memalign", "mtrace", "muntrace", "on_exit", "perror",
		"posix_memalign", "printf", "ptsname", "ptsname_r", "putc",
		"putc_unlocked", "putchar", "putchar_unlocked", "puts", "putw", "putwc",
		"putwc_unlocked", "putwchar", "putwchar_unlocked", "realloc",
		"reallocarray", "scanf", "sem_close", "sem_open", "sem_unlink",
		"shm_open", "shm_unlink", "siglongjmp", "sigsetjmp", "snprintf",
		"sprintf", "sscanf", "strerror", "strerror_r", "swprintf", "swscanf",
		"tempnam", "tmpfile", "tmpfile64", "tmpnam", "unlockpt", "valloc", "verr",
		"verrx", "vwarn", "vwarnx", "warn", "warnx", "wprintf", "wscanf"};
	for(unsigned i=0;i<(sizeof(unsafe_fnc)/sizeof(char*));++i)
	{
		if(strcmp(unsafe_fnc[i],name)==0)
			return true;
	}
	return false;
}

//proccess gimple call statement inside scan own function
void function_data::process_gimple_call(bb_data &status,gimple * stmt, bool &all_ok, std::list<const char*> &call_tree,
											bool &errno_valid, unsigned int &errno_stored, std::list<tree> &errno_ptr)
{
	tree fn_decl = gimple_call_fndecl(stmt);
	if (!fn_decl)
		return;
	const char* called_function_name = get_name(fn_decl);
	if (!called_function_name)
		return;
	int8_t return_number = RC_ASYNCH_SAFE;
	if (DECL_INITIAL  (fn_decl))
	{
		// in case of recurse, do nothing
		if (strcmp(get_name(this->get_fnc_decl()),called_function_name)==0)
			return;
		else
		{
			if ((return_number = scan_own_function(called_function_name,call_tree,nullptr))>=99)
			{
				depend_data save_dependencies;
				if (return_number==RC_CYCLIC)
				{
					return_number=RC_ASYNCH_SAFE;
					save_dependencies.cyclic=true;
				}
				else
					return_number-=100;
				save_dependencies.loc = gimple_location(stmt);
				save_dependencies.fnc = fn_decl;
				save_dependencies.stmt=stmt;

				//unscaned function, it can be found later, that it changes errno
				//(special instruction as placeholder for this change)
				instruction new_instr;
				new_instr.ic=IC_DEPEND;
				new_instr.var=nullptr;
				new_instr.instr_loc=gimple_location(stmt);
				status.instr_list.push_back(new_instr);
				save_dependencies.parent_instr_loc=status.instr_list.size();
				save_dependencies.parent_block_id=status.get_block_id();

				all_ok=false;
				data.dependencies_handled=false;
				this->depends.push_front(save_dependencies);
			}
		}
	}
	else
	{
		if(strcmp(called_function_name,"__errno_location")==0)
		{
			tree var = gimple_call_lhs (stmt);
			if(TREE_CODE (var) == SSA_NAME)
			{
				errno_valid = true;
				errno_stored = SSA_NAME_VERSION (var);
			}
			else if(TREE_CODE (var) == VAR_DECL)
			{
				const char* var_name = get_name(var);
				if (var_name)
				{
					errno_ptr.push_front(var);
				}
			}
		}
		else
		{
			return_number = is_handler_ok_fnc(called_function_name);
		}
	}
	//check for wrong function
	if (return_number == RC_NOT_ASYNCH_SAFE || return_number == RC_ASYNCH_UNSAFE)
	{
		all_ok=false;
		this->set_flag(FLG_NOT_SAFE,true);

		if (this->get_flag(FLG_IS_HANDLER))
			print_warning(this->get_fnc_decl(),fn_decl,gimple_location(stmt),return_number==RC_ASYNCH_UNSAFE);
		else
		{
			remember_error new_err;
			new_err.err_loc = gimple_location(stmt);
			new_err.err_fnc = fn_decl;
			new_err.err_fatal = return_number==RC_ASYNCH_UNSAFE;
			this->err_log.push_back(new_err);
		}

		if (return_number == RC_ASYNCH_UNSAFE)
			this->set_flag(FLG_FATAL,true);

		return;
	}
	//check if errno was not changed or exit was found
	else if (return_number == RC_ERRNO_CHANGED)
	{
		instruction new_instr;
		new_instr.ic=IC_CHANGE_ERRNO;
		new_instr.var=nullptr;
		new_instr.instr_loc=gimple_location(stmt);
		status.instr_list.push_back(new_instr);
	}
	else if (return_number == RC_SAFE_EXIT)
	{
		//status.exit_found=true;
		instruction new_instr;
		new_instr.ic=IC_EXIT;
		new_instr.var=nullptr;
		new_instr.instr_loc=gimple_location(stmt);
		status.instr_list.push_back(new_instr);
		status.is_exit=true;
	}
	//check for errno setter
	else if (return_number == RC_ERRNO_SETTER)
	{
		instruction new_instr;
		new_instr.ic=IC_RESTORE_ERRNO;
		new_instr.instr_loc=gimple_location(stmt);
		if((new_instr.var=get_var_from_setter_stmt (stmt)))
			status.instr_list.push_back(new_instr);
	}
}

//proccess gimple assign statement inside scan own function
void function_data::process_gimple_assign(bb_data &status, gimple * stmt, bool &errno_valid, unsigned int &errno_stored,
												errno_in_builtin &errno_builtin_storage, std::list<tree> &errno_ptr)
{
	//check if errno was stored or restored
	tree r_var = gimple_assign_rhs1 (stmt);
	tree l_var = gimple_assign_lhs (stmt);
	if (!r_var || !l_var)
		return;
	//if the l_var contain stored errno, destroy it
	//(if you try to store to variable again, it will be represented as two instructions, first destroy, then store)
	if (TREE_CODE (l_var) == VAR_DECL && is_var_in_list(l_var,this->stored_errno))
	{
		instruction new_instr;
		new_instr.ic=IC_DESTROY_STORAGE;
		new_instr.var=l_var;
		new_instr.instr_loc=gimple_location(stmt);
		status.instr_list.push_back(new_instr);
	}
	//store or restore check
	if (TREE_CODE (l_var) == VAR_DECL && TREE_CODE (r_var) == VAR_DECL)//store errno from storage
	{
		if (is_var_in_list(r_var,this->stored_errno))
		{
			instruction new_instr;
			new_instr.ic=IC_SAVE_FROM_VAR;
			new_instr.var=l_var;
			new_instr.from_var=r_var;
			new_instr.instr_loc=gimple_location(stmt);
			status.instr_list.push_back(new_instr);
			add_unique_to_list(l_var, this->stored_errno);
		}
	}
	else if (TREE_CODE (l_var) == MEM_REF)//restoring errno
	{
		l_var = TREE_OPERAND (l_var, 0);
		if (!l_var)
			return;
		if(TREE_CODE (l_var) == SSA_NAME)//get ID of mem_ref SSA_NAME variable(built in variable)
		{
			if (errno_valid && errno_stored == SSA_NAME_VERSION (l_var))
			{
				if (TREE_CODE (r_var) == VAR_DECL)
				{
					instruction new_instr;
					new_instr.ic=IC_RESTORE_ERRNO;
					new_instr.var=r_var;
					new_instr.instr_loc=gimple_location(stmt);
					status.instr_list.push_back(new_instr);
				}
				else if (TREE_CODE (r_var) == SSA_NAME && errno_builtin_storage.valid 
							&& errno_builtin_storage.id == SSA_NAME_VERSION (r_var))
				{
					if (errno_builtin_storage.var && TREE_CODE(errno_builtin_storage.var)==PARM_DECL)
					{
						unsigned counter=0;
						for (tree argument = DECL_ARGUMENTS (this->get_fnc_decl()) ; argument ; argument = TREE_CHAIN (argument))
						{
							if (strcmp(get_name(argument),get_name(errno_builtin_storage.var))==0)
							{
								instruction new_instr;
								new_instr.ic=IC_SET_FROM_PARM;
								new_instr.var=errno_builtin_storage.var;
								new_instr.param_pos=counter;
								new_instr.instr_loc=gimple_location(stmt);
								status.instr_list.push_back(new_instr);
								break;
							}
							++counter;
						}
					}
				}
				else
				{
					instruction new_instr;
					new_instr.ic=IC_CHANGE_ERRNO;
					new_instr.var=nullptr;
					new_instr.instr_loc=gimple_location(stmt);
					status.instr_list.push_back(new_instr);
				}
			}
		}
		else if (TREE_CODE (l_var) == VAR_DECL)//using own reference to errno
		{
			if (is_var_in_list(l_var,errno_ptr))
			{
				if (TREE_CODE (r_var) == VAR_DECL)
				{
					instruction new_instr;
					new_instr.ic=IC_RESTORE_ERRNO;
					new_instr.var=r_var;
					new_instr.instr_loc=gimple_location(stmt);
					status.instr_list.push_back(new_instr);
				}
				else if (TREE_CODE (r_var) == SSA_NAME && errno_builtin_storage.valid 
							&& errno_builtin_storage.id == SSA_NAME_VERSION (r_var))
				{
					if (errno_builtin_storage.var && TREE_CODE(errno_builtin_storage.var)==PARM_DECL)
					{
						unsigned counter=0;
						for (tree argument = DECL_ARGUMENTS (this->get_fnc_decl()) ; argument ; argument = TREE_CHAIN (argument))
						{
							if (strcmp(get_name(argument),get_name(errno_builtin_storage.var))==0)
							{
								instruction new_instr;
								new_instr.ic=IC_SET_FROM_PARM;
								new_instr.var=errno_builtin_storage.var;
								new_instr.param_pos=counter;
								new_instr.instr_loc=gimple_location(stmt);
								status.instr_list.push_back(new_instr);
								break;
							}
							++counter;
						}
					}
				}
				else
				{
					instruction new_instr;
					new_instr.ic=IC_CHANGE_ERRNO;
					new_instr.var=nullptr;
					new_instr.instr_loc=gimple_location(stmt);
					status.instr_list.push_back(new_instr);
				}
			}
		}
	}
	else if (TREE_CODE (r_var) == MEM_REF)//store errno
	{
		r_var = TREE_OPERAND (r_var, 0);
		if (!r_var)
			return;
		if(TREE_CODE (r_var) == SSA_NAME)//get ID of mem_ref SSA_NAME variable(built in variable)
		{
			if (errno_valid)
			{
				if (errno_stored == SSA_NAME_VERSION (r_var))
				{
					if (TREE_CODE (l_var) == VAR_DECL)
					{
						instruction new_instr;
						new_instr.ic=IC_SAVE_ERRNO;
						new_instr.var=l_var;
						new_instr.instr_loc=gimple_location(stmt);
						status.instr_list.push_back(new_instr);
						add_unique_to_list(l_var, this->stored_errno);
					}
					else if (TREE_CODE (l_var) == SSA_NAME)
					{
						errno_builtin_storage.valid=true;
						errno_builtin_storage.id=SSA_NAME_VERSION (l_var);
					}
				}
			}
		}
		else if(TREE_CODE (r_var) == VAR_DECL)//using own reference to errno
		{
			if (is_var_in_list(r_var,errno_ptr))
			{
				if (TREE_CODE (l_var) == VAR_DECL)
				{
					instruction new_instr;
					new_instr.ic=IC_SAVE_ERRNO;
					new_instr.var=l_var;
					new_instr.instr_loc=gimple_location(stmt);
					status.instr_list.push_back(new_instr);
					add_unique_to_list(l_var, this->stored_errno);
				}
				else if (TREE_CODE (l_var) == SSA_NAME)
				{
					errno_builtin_storage.valid=true;
					errno_builtin_storage.id=SSA_NAME_VERSION (l_var);
				}
			}
		}
		else if (TREE_CODE (r_var) == PARM_DECL)
		{
			if (TREE_CODE (l_var) == SSA_NAME)
			{
				errno_builtin_storage.var=r_var;
				errno_builtin_storage.valid=true;
				errno_builtin_storage.id=SSA_NAME_VERSION (l_var);
			}
		}
	}
	else if (TREE_CODE (r_var) == SSA_NAME && errno_builtin_storage.valid 
				&& errno_builtin_storage.id == SSA_NAME_VERSION (r_var))
	{
		if (TREE_CODE (l_var) == VAR_DECL && errno_builtin_storage.var==nullptr)
		{
			instruction new_instr;
			new_instr.ic=IC_SAVE_ERRNO;
			new_instr.var=l_var;
			new_instr.instr_loc=gimple_location(stmt);
			status.instr_list.push_back(new_instr);
			add_unique_to_list(l_var, this->stored_errno);
		}
	}
}

/* scan user declared function for asynchronous-unsafe functions
	name contains name of function, which should be scaned
	call_tree is list of nested calls of functions, it is necesery for recurse
	handler_found if this pointer is set, scaned function is handler and returns there, if handler was found or not
	returns 0 when function is not asynchronous-safe,
			  1 if it is safe and errno is not changed,
			  2 if it is safe, but errno may be changed,
			  4 if it is safe exit function
			  8 if it is errno setter
			 -1 if it is asynchronous-unsafe
			  this codes + 100 if it has unsolved dependencies (0 and -1 excluded)
*/
int8_t scan_own_function (const char* name,std::list<const char*> &call_tree,bool *handler_found)
{
	if (!name)
		return RC_ASYNCH_SAFE;
	int8_t return_number=RC_ASYNCH_SAFE;
	//check for undirect recurse and should stop infinite call of this function
	for (const char* fnc: call_tree)
	{
		if (strcmp(name,fnc)==0)
			return RC_CYCLIC;
		//this means that this function is ok, but wasn't scaned entirely
		//(can't scan this function, because it undirectly depends on itself),
		//function that called this function will depend on this function
		//this should be solved in handle_dependencies()
	}
	call_tree.push_back(name);
	basic_block bb;
	bool all_ok=false;

	bool errno_valid=false;
	unsigned int errno_stored=0;
	errno_in_builtin errno_builtin_storage;
	std::list<tree> errno_ptr;

	for (function_data &obj: data.fnc_list)
	{
		if (strcmp(get_name(obj.get_fnc_decl()),name)==0)
		{
			//check if it was already scaned
			if (handler_found != nullptr)
			{
				*handler_found=true;
				if (obj.get_flag(FLG_ERRNO_CHANGED) && !obj.get_flag(FLG_IS_HANDLER))
				{
					obj.set_flag(FLG_WAS_ERR,true);
					print_errno_warning(obj.get_fnc_decl(),obj.errno_loc);
				}
				if (obj.get_flag(FLG_IS_HANDLER) && obj.get_flag(FLG_SCANED))
					return return_number;
				obj.set_flag(FLG_IS_HANDLER,true);
				if (obj.get_flag(FLG_IS_OK))
					return return_number;
				if (obj.get_flag(FLG_NOT_SAFE))
				{
					while (!obj.err_log.empty())
					{
						remember_error err = obj.err_log.front();
						print_warning(obj.get_fnc_decl(),err.err_fnc,err.err_loc,err.err_fatal);
						obj.err_log.pop_front();
					}
					break;
				}
				if(obj.get_flag(FLG_SCANED))
					return return_number;
			}
			else
			{
				if (obj.get_flag(FLG_NOT_SAFE))
				{
					if (obj.get_flag(FLG_FATAL))
						return_number=RC_ASYNCH_UNSAFE;
					else
						return_number=RC_NOT_ASYNCH_SAFE;
					call_tree.pop_back();
					return return_number;
				}
				else if (obj.get_flag(FLG_ERRNO_CHANGED))
				{
					return_number= RC_ERRNO_CHANGED;
					if (!obj.get_flag(FLG_IS_OK))
						return_number+=100;
					call_tree.pop_back();
					return return_number;
				}
				else if (obj.get_flag(FLG_IS_EXIT))
				{
					return_number=RC_SAFE_EXIT;
					if (!obj.get_flag(FLG_IS_OK))
						return_number+=100;
					call_tree.pop_back();
					return return_number;
				}
				else if (obj.get_flag(FLG_IS_ERRNO_SETTER))
				{
					return_number=RC_ERRNO_SETTER;
					if (!obj.get_flag(FLG_IS_OK))
						return_number+=100;
					call_tree.pop_back();
					return return_number;
				}
				else if (obj.get_flag(FLG_SCANED))
				{
					return_number=RC_ASYNCH_SAFE;
					if (!obj.get_flag(FLG_IS_OK))
					{
						bool all_cyclic=true;
						for (depend_data &depends: obj.depends)
						{
							if(!depends.cyclic)
								all_cyclic=false;
						}
						if(all_cyclic)
							return_number=RC_CYCLIC;
						else
							return_number+=100;
					}
					call_tree.pop_back();
					return return_number;
				}
			}
			all_ok=true;
			//start the scan
			FOR_ALL_BB_FN(bb, obj.get_fnc_ptr())
			{
				bb_data status(bb->index);

				status.input_set.insert(pseudo_errno);
				status.output_set.insert(pseudo_errno);

				gimple_stmt_iterator gsi;
				for (gsi = gsi_start_bb (bb); !gsi_end_p (gsi); gsi_next (&gsi))
				{
					gimple * stmt = gsi_stmt (gsi);
					//print_gimple_stmt (stderr,stmt,0,0);
					if (gimple_code(stmt)==GIMPLE_CALL)
						obj.process_gimple_call(status, stmt, all_ok, call_tree, errno_valid, errno_stored, errno_ptr);
					else if (!obj.get_flag(FLG_WAS_ERR) && gimple_code(stmt)==GIMPLE_ASSIGN)
						obj.process_gimple_assign(status, stmt, errno_valid, errno_stored, errno_builtin_storage, errno_ptr);
				}
				if (!obj.get_flag(FLG_WAS_ERR))
				{
					edge e;
					edge_iterator ei;

					FOR_EACH_EDGE(e, ei, bb->preds)
					{
					  basic_block pred = e->src;
					  status.preds.push_back(pred->index);
					}
					obj.block_status.push_back(status);
				}
			}
			//scan complete, start CFG analysis
			if (!obj.get_flag(FLG_WAS_ERR) && obj.depends.empty())
			{
				obj.analyze_CFG();
				if (obj.get_flag(FLG_IS_HANDLER) && obj.get_flag(FLG_ERRNO_CHANGED))
				{
					obj.set_flag(FLG_WAS_ERR,true);
					print_errno_warning(obj.get_fnc_decl(),obj.errno_loc);
				}
			}
			obj.set_flag(FLG_SCANED,true);
			//return value according the scan results
			if (obj.get_flag(FLG_FATAL))
				return_number=RC_ASYNCH_UNSAFE;
			else if (obj.get_flag(FLG_NOT_SAFE))
				return_number=RC_NOT_ASYNCH_SAFE;
			else if (obj.get_flag(FLG_ERRNO_CHANGED))
				return_number=RC_ERRNO_CHANGED;
			else if (obj.get_flag(FLG_IS_EXIT))
				return_number=RC_SAFE_EXIT;
			else if (obj.get_flag(FLG_IS_ERRNO_SETTER))
				return_number=RC_ERRNO_SETTER;
			if (return_number == RC_NOT_ASYNCH_SAFE || return_number == RC_ASYNCH_UNSAFE)
			{
				call_tree.pop_back();
				return return_number;
			}
			// if everything scaned succesfully function is asynchronous-safe
			obj.set_flag(FLG_IS_OK,all_ok);
		}
	}
	call_tree.pop_back();
	//if there are unsolved dependencies return_number is modified by +100
	//dependencies will be solved later, when we have more informations
	if (!all_ok)
		return_number+=100;
	return return_number;
}

//print warning about non asynchronous-safe function 'fnc' in signal handler 'handler'
inline
void print_warning(tree handler,tree fnc,location_t loc,bool fatal)
{
	const char* handler_name = get_name(handler);
	const char* fnc_name = get_name(fnc);
	std::string msg = "asynchronous-unsafe function";
	if (!fatal)
		msg = "possible " + msg;
	if(!isatty(STDERR_FILENO))
	{
		msg += " ‘";
		msg += fnc_name;
		msg += "‘ in signal handler";
		msg += " ‘";
		msg += handler_name;
		msg += "‘";
		msg += " [-fplugin=";
		msg += plugin_name;
		msg += "]";
	}
	else
	{
		msg += " ‘\033[1;1m";
		msg += fnc_name;
		msg += "\033[0m‘ in signal handler";
		msg += " ‘\033[1;1m";
		msg += handler_name;
		msg += "\033[0m‘";
		msg += " [\033[1;35m-fplugin=";
		msg += plugin_name;
		msg += "\033[0m]";
	}
	warning_at(loc,0,"%s",msg.c_str());
}

//print warning about changed errno in signal handler 'handler'
inline void print_errno_warning(tree handler,location_t loc)
{
	const char* handler_name = get_name(handler);
	std::string msg = "errno may be changed in signal handler";
	if(!isatty(STDERR_FILENO))
	{

		msg += " ‘";
		msg += handler_name;
		msg += "‘";
		msg += " [-fplugin=";
		msg += plugin_name;
		msg += "]";
	}
	else
	{
		msg += " ‘\033[1;1m";
		msg += handler_name;
		msg += "\033[0m‘";
		msg += " [\033[1;35m-fplugin=";
		msg += plugin_name;
		msg += "\033[0m]";
	}
	warning_at(loc,0,"%s",msg.c_str());
}



// We must assert that this plugin is GPL compatible
int plugin_is_GPL_compatible;

static struct plugin_info handler_check_gcc_plugin_info =
{ release_version, "This plugin scans signal handlers for violations of signal-safety rules" };

namespace {
const pass_data handler_check_pass_data =
{
	GIMPLE_PASS,
	"handler_check_pass",               /* name */
	OPTGROUP_NONE,                      /* optinfo_flags */
	TV_NONE,                            /* tv_id */
	PROP_gimple_any,                    /* properties_required */
	0,                                  /* properties_provided */
	0,                                  /* properties_destroyed */
	0,                                  /* todo_flags_start */
	0                                   /* todo_flags_finish */
};

struct handler_check_pass : gimple_opt_pass
{
	handler_check_pass(gcc::context * ctx) :
	gimple_opt_pass(handler_check_pass_data, ctx)
	{}

	virtual unsigned int execute(function * fun) override
	{
		basic_block bb;
		tree handler=nullptr;
		function_data new_fnc(fun,current_function_decl);
		data.fnc_list.push_front(new_fnc);
		//Start look for handlers
		FOR_ALL_BB_FN(bb, fun)
		{

			gimple_stmt_iterator gsi;
			//try to identify signal handler
			for (gsi = gsi_start_bb (bb); !gsi_end_p (gsi); gsi_next (&gsi))
			{
				gimple * stmt = gsi_stmt (gsi);
				if (gimple_code(stmt)==GIMPLE_CALL)
					handler=get_handler(stmt);
				else if (gimple_code(stmt)==GIMPLE_ASSIGN)
				{
					//expand COMPONENT_REF into separated strings(assign to .sa_handler in some struct)
					if (TREE_CODE(gimple_assign_lhs(stmt))==COMPONENT_REF)
					{
						tree node,op0,op1,op2;
						node = TREE_OPERAND (gimple_assign_lhs(stmt), 0);
						op2 = TREE_OPERAND (gimple_assign_lhs(stmt), 1);
						if (TREE_CODE(node)==COMPONENT_REF)
						{
							op0 = TREE_OPERAND (node, 0);
							op1 = TREE_OPERAND (node, 1);

							if (TREE_CODE(op1)==FIELD_DECL)
							{
								if (!DECL_NAME(op1))
									continue;
								const char *field_name = identifier_to_locale (IDENTIFIER_POINTER (DECL_NAME (op1)));
								if (strcmp(field_name,"__sigaction_handler")==0)
								{
									if (!DECL_NAME(op2))
										continue;
									field_name = identifier_to_locale (IDENTIFIER_POINTER (DECL_NAME (op2)));
									if (strcmp(field_name,"sa_handler")==0 || strcmp(field_name,"sa_sigaction")==0)
									{
										const char *var_name=nullptr;
										if (TREE_CODE(op0)==VAR_DECL)
											var_name = identifier_to_locale (IDENTIFIER_POINTER (DECL_NAME (op0)));
										else if (TREE_CODE(op0)==MEM_REF)
										{
											op0 = TREE_OPERAND (op0, 0);
											var_name = identifier_to_locale (IDENTIFIER_POINTER (DECL_NAME (op0)));
										}
										if (var_name!= nullptr)
										{
											handler_in_var new_var_handler;
											new_var_handler.var_name=var_name;
											new_var_handler.handler=gimple_assign_rhs1 (stmt);
											data.possible_handlers.push_front(new_var_handler);
										}
									}
								}
							}
						}
					}
				}
				if (handler!=nullptr)//handler found, add to list of handlers to scan
				{
					data.handlers.push_front(handler);
					handler=nullptr;
				}
			}
		}
		//End look for handlers

		//if new setter was found, check already checked functions with new setters
		while (data.added_new_setter)
		{
			data.added_new_setter=false;
			for (function_data &obj: data.fnc_list)
			{
				basic_block bb;
				FOR_ALL_BB_FN(bb, obj.get_fnc_ptr())
				{

					gimple_stmt_iterator gsi;
					for (gsi = gsi_start_bb (bb); !gsi_end_p (gsi); gsi_next (&gsi))
					{
						gimple * stmt = gsi_stmt (gsi);
						if (gimple_code(stmt)==GIMPLE_CALL)
						{
							handler = data.scan_own_handler_setter(stmt,obj.get_fnc_decl());
							if (handler!=nullptr)
							{
								data.handlers.push_front(handler);
								handler=nullptr;
							}
						}
					}
				}
			}
		}

		//scan all identified signal handlers
		std::list<tree>::iterator it = data.handlers.begin();
		std::list<tree>::iterator it_next=it;
		while(it!=data.handlers.end())
		{
			++it_next;
			handler=*it;

			if (handler != nullptr)
			{
				bool found=false;
				std::list<const char*> call_tree;
				scan_own_function(get_name(handler),call_tree,&found);
				if (found)
					data.handlers.erase(it);
			}
			else
				data.handlers.erase(it);
			it=it_next;
		}
		//end handlers check

		//if there are unsolved dependencies try to handle them
		if (!data.dependencies_handled)
			data.handle_dependencies();

		return 0;
	}

	virtual handler_check_pass *clone() override
	{
		// We do not clone ourselves
		return this;
	}
};
}

int plugin_init(struct plugin_name_args *plugin_info,
				struct plugin_gcc_version *version)
{
	if(!plugin_default_version_check(version, &gcc_version))
	{
		std::cerr << "This GCC plugin is for version " << GCCPLUGIN_VERSION_MAJOR
			<< "." << GCCPLUGIN_VERSION_MINOR << "\n";
		return 1;
	}

	register_callback(plugin_info->base_name,
		/* event */ PLUGIN_INFO,
		/* callback */ NULL,
		/* user_data */
		&handler_check_gcc_plugin_info);

	// Register the phase right after cfg
	struct register_pass_info pass_info;

	pass_info.pass = new handler_check_pass(g);
	pass_info.reference_pass_name = "cfg";
	pass_info.ref_pass_instance_number = 1;
	pass_info.pos_op = PASS_POS_INSERT_AFTER;

	register_callback(plugin_info->base_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &pass_info);


	return 0;
}
