---
title: ICSE2024--Blockwatchdog学习（一）
date: 2024-05-09 10:26:19
tags: [Defi安全, 工具源码学习]
categories: Defi安全
description: 摘要：ICSE2024--BlockWatchdog源码学习(一)
---

## 1. blockwatchdog.py

该文件用以处理对应的命令行输入和相应的输出

输入对应的检测合约地址、公链以及对应区块即可。

### 1）流信息的构建

调用`Contract.py中的Contract()`实例化对应的合约。

获得分析合约中所有的函数签名，以及函数签名的中的外部调用

```python
    original_contract = Contract(
        source["platform"],
        source["logic_addr"],
        source["storage_addr"],
        source["func_sign"],
        source["block_number"],
        source["caller"],
        source["call_site"],
        source["level"],
        source["env_val"],
    )
    func_sign_list = original_contract.get_func_sign_list()
    external_call_in_func_sigature = (
        original_contract.get_external_call_in_func_sigature()
    )
```

### 2）跨合约调用图的构建

对合约中每个外部调用进行跨合约调用图的构建

```python
while len(external_call_in_func_sigature) > 0:
    source = {
        "platform": args.platform,
        "logic_addr": args.logic_addr,
        "storage_addr": storage_addr,
        "func_sign": "",
        "block_number": args.block_number,
        "caller": "msg.sender",
        "caller_func_sign": "",
        "call_site": "",
        "level": 0,
        "env_val": None,
    }
    source["func_sign"] = external_call_in_func_sigature.pop()
    cross_contract_call_graph = CallGraph(source, contracts, source["platform"])
    cross_contract_call_graph.construct_cross_contract_call_graph()
    # 构建对应的跨合约调用图，这里利用DFS构建对应的跨合约调用图
    visited_contracts = (
        visited_contracts + cross_contract_call_graph.visited_contracts
    )
    visited_funcs = visited_funcs + cross_contract_call_graph.visited_funcs
    call_depth = cross_contract_call_graph.max_level

    if call_depth > max_call_depth:
        max_call_depth = call_depth
    # 最大调用长度的相关限制

    call_graph_str = cross_contract_call_graph.get_output()
    call_paths.append(call_graph_str)
    # 相应的调用路径的输出

m_call_depth = max_call_depth
```

### 3）污点分析

首先调用`FlowAnalysis()`实例化对应的检测器，并进行相应的检测

```python
    detector = FlowAnalysis(
        source["logic_addr"],
        contracts,
        func_sign_list,
        store_external_call_in_func_sigature_list,
        visited_contracts,
        visited_funcs,
    )        
    result["is_attack"], result["attack_matrix"] = detector.detect()
    #进行相应的污点分析，漏洞检测
    result["semantic_features"]["op_creation"][
        "op_multicreate"
    ] = detector.op_multicreate_analysis()
    result["semantic_features"]["op_creation"][
        "op_solecreate"
    ] = detector.op_solecreate_analysis()
    result["semantic_features"]["op_selfdestruct"] = detector.op_selfdestruct_analysis()
    result["semantic_features"]["op_env"] = detector.tainted_env_call_arg()

    result["external_call"]["externalcall_inhook"] = detector.externalcall_inhook()
    result["external_call"][
        "externalcall_infallback"
    ] = detector.externalcall_infallback()

    sensitive_callsigs = detector.get_sig_info()
    victim_callback_info, attack_reenter_info = detector.get_reen_info()
```

## 2. Contract.py

该文件主要用于对输入的合约地址进行处理，获取相应的字节码，并且调用gigahorse反编译的引擎进行相应的处理

最关键的是`self.analyze()`函数

```python
    def analyze(self):
        logging.info("analyzing " + self.logic_addr)
        logging.info("caller " + self.caller)
        logging.info("call_site " + self.call_site)
        logging.info("func_sign " + self.func_sign)
        self.set_url()
        #设置web3库的相应url
        self.download_bytecode()
        #如果没检测过相应的地址，则通过web3获取字节码保存到指定位置
        if os.path.exists(global_params.CONTRACT_PATH + self.logic_addr + ".hex"):
            self.analyze_contract()
            # 调用gigahorse，对合约字节码进行反编译处理，生成相应的数据流和控制流关系
            self.set_func()
			# 调用gigahorse解析结果，获取对应的函数位置和函数签名
            self.set_callArgVals()
            self.set_knownArgVals()
            # 保存对应的外部调用的Call位置，以及对应的函数参数
            
            logging.info(
                "call arg vals obtained from the previous contract call {}".format(
                    self.callArgVals
                )
            )
            logging.info(
                "known arg vals in the current contract call {}".format(
                    self.knownArgVals
                )
            )
            if self.origin is True:
                if not self.createbin:
                    # remove key 0x0 from the dict  func_sign_dict
                    del self.func_sign_dict["0x0"]
                for func in self.func_sign_dict.keys():
                    logging.info(
                        "set external calls in function " + self.func_sign_dict[func]
                    )
                    self.set_external_calls(func, self.func_sign_dict[func])
            else:
                self.set_external_calls(self.func, self.func_sign)
            ## 设置对应的外部调用，最关键的一步
```

`self.set_external_calls()`调用链的获取，主要依赖于gigahorse的分析能力

```python
    def set_external_calls(self, func, func_sign):
        loc_external_call = (
            "./gigahorse-toolchain/.temp/"
            + self.logic_addr
            + "/out/Leslie_ExternalCallInfo.csv"
        )
        if os.path.exists(loc_external_call) and (
            os.path.getsize(loc_external_call) > 0
        ):
            df_external_call = pd.read_csv(loc_external_call, header=None, sep="	")
            df_external_call.columns = [
                "func",
                "callStmt",
                "callOp",
                "calleeVar",
                "numArg",
                "numRet",
            ]
            try:
                df_external_call = df_external_call.loc[
                    df_external_call["func"] == func
                ]
                #找到函数签名中存在外部调用的函数吊命
            except Exception:
                pass
        else:
            df_external_call = pd.DataFrame()

        if self.origin is True:
            for i in range(len(df_external_call)):
                func = df_external_call.iloc[i]["func"]
                # find functions with external calls
                if self.func_sign_dict[func] not in self.external_call_in_func_sigature:
                    self.external_call_in_func_sigature.append(
                        self.func_sign_dict[func]
                    )
                #将对应存在外部调用函数保存到对应的属性中

        # for callee identification
        loc_callee_const = (
            "./gigahorse-toolchain/.temp/"
            + self.logic_addr
            + "/out/Leslie_ExternalCall_Callee_ConstType.csv"
        )
        # 常量保存的调用合约地址
        if os.path.exists(loc_callee_const) and (os.path.getsize(loc_callee_const) > 0):
            df_callee_const = pd.read_csv(loc_callee_const, header=None, sep="	")
            df_callee_const.columns = ["func", "callStmt", "callee"]
        else:
            df_callee_const = pd.DataFrame()

        loc_callee_storage = (
            "./gigahorse-toolchain/.temp/"
            + self.logic_addr
            + "/out/Leslie_ExternalCall_Callee_StorageType.csv"
        )
        # Storage中保存的调用合约地址
        if os.path.exists(loc_callee_storage) and (
            os.path.getsize(loc_callee_storage) > 0
        ):
            df_callee_storage = pd.read_csv(loc_callee_storage, header=None, sep="	")
            df_callee_storage.columns = [
                "func",
                "callStmt",
                "storageSlot",
                "byteLow",
                "byteHigh",
            ]
        else:
            df_callee_storage = pd.DataFrame()

        loc_callee_storage_proxy = (
            "./gigahorse-toolchain/.temp/"
            + self.logic_addr
            + "/out/Leslie_ExternalCall_Callee_StorageType_ForProxy.csv"
        )
        # 代理合约的stroage中保存的调用合约地址
        if os.path.exists(loc_callee_storage_proxy) and (
            os.path.getsize(loc_callee_storage_proxy) > 0
        ):
            df_callee_storage_proxy = pd.read_csv(
                loc_callee_storage_proxy, header=None, sep="	"
            )
            df_callee_storage_proxy.columns = ["func", "callStmt", "storageSlot"]
        else:
            df_callee_storage_proxy = pd.DataFrame()

        # for target function signature identification
        loc_fs_const = (
            "./gigahorse-toolchain/.temp/"
            + self.logic_addr
            + "/out/Leslie_ExternalCall_FuncSign_ConstType.csv"
        )
        # 常量方式取出对应的调用函数签名
        if os.path.exists(loc_fs_const) and (os.path.getsize(loc_fs_const) > 0):
            df_fs_const = pd.read_csv(loc_fs_const, header=None, sep="	")
            df_fs_const.columns = ["func", "callStmt", "funcSign"]
        else:
            df_fs_const = pd.DataFrame()

        loc_fs_proxy = (
            "./gigahorse-toolchain/.temp/"
            + self.logic_addr
            + "/out/Leslie_ExternalCall_FuncSign_ProxyType.csv"
        )
        # 代理的方式取出对应的函数签名
        
        if os.path.exists(loc_fs_proxy) and (os.path.getsize(loc_fs_proxy) > 0):
            df_fs_proxy = pd.read_csv(loc_fs_proxy, header=None, sep="	")
            df_fs_proxy.columns = ["func", "callStmt"]
        else:
            df_fs_proxy = pd.DataFrame()

        loc_callee_funarg = (
            "./gigahorse-toolchain/.temp/"
            + self.logic_addr
            + "/out/Leslie_ExternalCall_Callee_FuncArgType.csv"
        )
        #外部参数传入的调用函数签名
        if os.path.exists(loc_callee_funarg) and (
            os.path.getsize(loc_callee_funarg) > 0
        ):
            df_callee_funarg = pd.read_csv(loc_callee_funarg, header=None, sep="	")
            df_callee_funarg.columns = ["func", "callStmt", "pubFun", "argIndex"]
        else:
            df_callee_funarg = pd.DataFrame()

        transfer_target_call = self.get_sensitive_transfer_target()
        # 查看外部调用中是否存在敏感的transfer调用操作
        
        log.info("transfer target call")
        log.info(transfer_target_call)
        # for every call point in the contract, try to find its call target
        for i in range(len(df_external_call)):
            call_stmt = df_external_call.iloc[i]["callStmt"]
            # find target callee's logic address
            external_call = {
                "logic_addr": "",  # target contract address
                "storage_addr": "",  # target contract storage address
                "funcSign": "",  # target function signature (after)
                "caller": "",  # caller address (msg.sender for the origin) (current)
                "call_site": "",  # external call site (current)
                "known_args": {},  # record all known args from env and storage, etc.
                "transfer_target": "",
            }
            if call_stmt in transfer_target_call:
                external_call["transfer_target"] = self.knownArgVals[call_stmt][0]
                log.info("transfer target")
                log.info(external_call["transfer_target"])

            if len(df_callee_const) != 0:
                df_temp = df_callee_const.loc[df_callee_const["callStmt"] == call_stmt]
                if len(df_temp) > 0:
                    external_call["logic_addr"] = list(df_temp["callee"])[0].replace(
                        "000000000000000000000000", ""
                    )
            # 如何调用者地址保存在了常量中，进行相应处理

            if len(df_callee_storage) != 0:
                df_temp = df_callee_storage.loc[
                    df_callee_storage["callStmt"] == call_stmt
                ]
                if len(df_temp) > 0:
                    if self.storage_addr in global_params.STORAGE_SPACE.keys():
                        if (
                            list(df_temp["storageSlot"])[0]
                            in global_params.STORAGE_SPACE[self.storage_addr].keys()
                        ):
                            external_call["logic_addr"] = global_params.STORAGE_SPACE[
                                self.storage_addr
                            ][list(df_temp["storageSlot"])[0]]
                        else:
                            external_call["logic_addr"] = self.get_storage_content(
                                list(df_temp["storageSlot"])[0],
                                list(df_temp["byteLow"])[0],
                                list(df_temp["byteHigh"])[0],
                            )
                            global_params.STORAGE_SPACE[self.storage_addr][
                                list(df_temp["storageSlot"])[0]
                            ] = external_call["logic_addr"]
                    else:
		 #如果没提供对应的storage_address的情况
                        global_params.STORAGE_SPACE[self.storage_addr] = {}
                        external_call["logic_addr"] = self.get_storage_content(
                            list(df_temp["storageSlot"])[0],
                            list(df_temp["byteLow"])[0],
                            list(df_temp["byteHigh"])[0],
                        )
        # 如果调用者地址保存在了storage中，输入对应的插槽地址偏移量和对应的字节长度，获取对应的调用地址，该函数通过web3.get_storage_at()获得对应的地址
                        global_params.STORAGE_SPACE[self.storage_addr][
                            list(df_temp["storageSlot"])[0]
                        ] = external_call["logic_addr"]
            # 将插槽对应地址建立映射

            if len(df_callee_storage_proxy) != 0:
                df_temp = df_callee_storage_proxy.loc[
                    df_callee_storage_proxy["callStmt"] == call_stmt
                ]
                if len(df_temp) > 0:
                    if self.storage_addr in global_params.STORAGE_SPACE.keys():
                        if (
                            list(df_temp["storageSlot"])[0]
                            in global_params.STORAGE_SPACE[self.storage_addr].keys()
                        ):
                            external_call["logic_addr"] = global_params.STORAGE_SPACE[
                                self.storage_addr
                            ][list(df_temp["storageSlot"])[0]]
                        else:
                            external_call["logic_addr"] = self.get_storage_content(
                                list(df_temp["storageSlot"])[0], 0, 19
                            )
                            global_params.STORAGE_SPACE[self.storage_addr][
                                list(df_temp["storageSlot"])[0]
                            ] = external_call["logic_addr"]
                    else:
                        global_params.STORAGE_SPACE[self.storage_addr] = {}
                        external_call["logic_addr"] = self.get_storage_content(
                            list(df_temp["storageSlot"])[0], 0, 19
                        )
			# 同理，获取storage_proxy中对应的调用函数地址 
            
            # find callee got from the func arg (called by caller), and try to recover the know args
            if len(df_callee_funarg) != 0:
                df_temp = df_callee_funarg.loc[
                    df_callee_funarg["callStmt"] == call_stmt
                ]
                if len(df_temp) > 0:
                    # find the function that use the itself's public func args
                    for j in range(len(df_temp)):
                        if list(df_temp["func"])[j] == list(df_temp["pubFun"])[j]:
                            temp_index = int(list(df_temp["argIndex"])[j])
                            if temp_index in self.callArgVals.keys():
                                external_call["logic_addr"] = self.callArgVals[
                                    temp_index
                                ]
                                logging.info(
                                    "known target vals: {}".format(
                                        external_call["logic_addr"]
                                    )
                                )

            # record all args (const address, constants, and other env vars (e.g., msg.sender, address(this)))
            if call_stmt in self.knownArgVals.keys():
                external_call["known_args"] = self.knownArgVals[call_stmt]

            # to differentiate the delegatecall and normal call
            if df_external_call.iloc[i]["callOp"] == "DELEGATECALL":
                # the storage addr is still the current addr
                external_call["storage_addr"] = self.logic_addr
                external_call["caller"] = self.caller
                external_call["call_site"] = self.call_site
            else:
                external_call["storage_addr"] = external_call["logic_addr"]
                external_call["caller"] = self.logic_addr
                external_call["call_site"] = call_stmt

            # label the function signature
            if len(df_fs_const) != 0:
                df_temp = df_fs_const.loc[df_fs_const["callStmt"] == call_stmt]
                if len(df_temp) > 0:
                    external_call["funcSign"] = list(df_temp["funcSign"])[0][:10]

            if len(df_fs_proxy) != 0:
                df_temp = df_fs_proxy.loc[df_fs_proxy["callStmt"] == call_stmt]
                if len(df_temp) > 0:
                    external_call["funcSign"] = func_sign
            self.external_calls.append(external_call)
			# 得到对应的调用合约以及函数签名后，保存在self.external_calls中
```

## 3. flow_analysis.py

实例化过程传入了合约地址，函数签名，外部调用函数签名，调用路径上的合约以及函数

目前针对 bad_randomness、DOS、reentrancy和price_manipulation四种漏洞进行检测

### 1）bad_randomness

```python
def intraprocedural_br_analysis(self):
    for key in self.contracts.keys():
        if self.contracts[key].level == 0:
            temp_address = key.split("_")[2]
            temp_funcSign = key.split("_")[3]
            if "__function_selector__" in key:
                temp_funcSign = "__function_selector__"
            loc = (
                global_params.OUTPUT_PATH
                + ".temp/"
                + temp_address
                + "/out/Leslie_SensitiveOpOfBadRandomnessAfterExternalCall.csv"
            )
            if os.path.exists(loc) and (os.path.getsize(loc) > 0):
                df = pd.read_csv(loc, header=None, sep="	")
                df.columns = ["funcSign", "callStmt", "sensitiveVar", "sourceOp"]
                # it is not neccessary to label the func, just focus on the callStmt
                df = df.loc[df["funcSign"] == temp_funcSign]
                if len(df) != 0:
                    return True
    return False
```

看了Datalog中`Leslie_SensitiveOpOfBadRandomnessAfterExternalCall`的实现，感觉这里的检测可能不太准确。

### 2) DOS

```python
def intraprocedural_dos_analysis(self):
    for key in self.contracts.keys():
        if self.contracts[key].level == 0:
            temp_address = key.split("_")[2]
            temp_funcSign = key.split("_")[3]
            if "__function_selector__" in key:
                temp_funcSign = "__function_selector__"
            loc = (
                global_params.OUTPUT_PATH
                + ".temp/"
                + temp_address
                + "/out/Leslie_SensitiveOpOfDoSAfterExternalCall.csv"
            )
            if os.path.exists(loc) and (os.path.getsize(loc) > 0):
                df = pd.read_csv(loc, header=None, sep="	")
                df.columns = [
                    "funcSign",
                    "callStmt",
                    "callRetVar",
                    "callRetIndex",
                    "sensitiveVar",
                ]
                # it is not neccessary to label the func, just focus on the callStmt
                df = df.loc[df["funcSign"] == temp_funcSign]
                if len(df) != 0:
                    return True
    return False
```

datalog对应的`Leslie_SensitiveOpOfDoSAfterExternalCall`规则如下：

```datalog
// sensitive operations related to dos
.decl Leslie_SensitiveOpOfDoSAfterExternalCall(funcSign:symbol, callStmt:Statement, callRetVar:Variable, callRetIndex:number, sensitiveVar:Variable)
.output Leslie_SensitiveOpOfDoSAfterExternalCall
Leslie_SensitiveOpOfDoSAfterExternalCall(funcSign, callStmt, callRetVar, callRetIndex, target) :-
  ExternalCall_ActualReturn(callStmt, callRetVar, callRetIndex),
  //捕获特定的外部调用，及其相应的返回变量及索引
  CallToSignature(callStmt, sigText),
  (sigText = "getCurrentRoundInfo(uint256)";
  sigText = "_getCurrentRoundInfo()";
  sigText = "getCurrentRoundInfo()";
  sigText = "getCurrentRoundInfo2()"),
  // 找到函数签名的sigText的签名
  DataFlows(callRetVar, target),
  //判断这样的外部调用返回是否流向一个敏感操作
  // consider the flow
  Leslie_AddressAssertionOp(funcSign, target),
  Leslie_Statement_Function(callStmt, func),
  Leslie_FunctionSelector(func, funcSign).

.decl Leslie_AddressAssertionOp(funcSign: symbol, addrRet:Variable)
Leslie_AddressAssertionOp(funcSign, addrRet) :-
  //敏感操作的定义
  (EQVars(target,addrRet,res);EQVars(addrRet,target,res)),
  //判断是否有比较或数据流动，指示外部调用的结果如何被用来作为跳转条件的一部分
  // flow to the predicate (tobe used)
  DataFlows(res, predicate),
  JUMPI(stmt,_,predicate),
  //如果断言失败，JUMPI指令会导致合约跳过后续操作
  Leslie_Statement_Function(stmt, func),
  // should be the const or the argument
  Variable_Value(target, val),
  Value_Length(val, len),
  len = 42,
  Leslie_FunctionSelector(func, funcSign).
```

通过跟踪从外部调用返回的值，检查这些值是否流向了进行关键判断（如地址断言）的操作，代码可以识别可能导致合约执行非预期中断的模式。

这种中断可能因资源耗尽（如无限循环）、执行跳转（如错误处理），或其他异常行为而引起合约服务中断，构成 DoS 漏洞。

但感觉这里的检测也不是很精确。

### 3）price manipulation

价格操作漏洞的检测与ISSTA2023DefiTainter的检测方法一致

分为两种检测，一是合约内的污点检测，二是跨合约的污点分析

- intraprocedural_analysis:

```python
def intraprocedural_analysis(self):
    for key in self.contracts.keys():
        temp_address = key.split("_")[2]
        temp_funcSign = key.split("_")[3]
        loc = (
            "./gigahorse-toolchain/.temp/"
            + temp_address
            + "/out/Leslie_FLTaintedVarToSensitiveVar.csv"
        )

        if os.path.exists(loc) and (os.path.getsize(loc) > 0):
            df = pd.read_csv(loc, header=None, sep="	")
            df.columns = ["funcSign", "taintedVar", "sensitiveVar"]
            df = df.loc[df["funcSign"] == temp_funcSign]
            if len(df) != 0:
                log.info(key)
                return True
    return False
```

进入datalog中`Leslie_FLTaintedVarToSensitiveVar`查看检测细节：

具体逻辑为：

- 首先检测`balanceOf（）`这样外部函数调用的返回值，将其作为攻击者可操控的source，

- 随后攻击者查看transfer的敏感的调用地址攻击者是否可操控，如果可以的话，那么transfer函数的转账金额就被认为是一个敏感变量
- 随后判断source和sink之间是否有对应的传播路径，如果有的话，则认为存在漏洞，保存在对应的csv文件中

```datalog
.decl Leslie_FLTaintedVarToSensitiveVar(funcSign:symbol, taintedVar:Variable, sensitiveVar: Variable)
.output Leslie_FLTaintedVarToSensitiveVar
Leslie_FLTaintedVarToSensitiveVar(funcSign, var1, var2):-
  Leslie_FLTaintedVar(funcSign, var1),
  //寻找对应的taint source污点源
  !SLOAD(_, _, var1),
  Leslie_FLSensitiveVar(funcSign, var2),
  //寻找对应的taint sink污点汇--敏感操作
  DataFlows(var1, var2),
  //source和sink之间是否存在对应的路径
  var1 != var2,
  funcSign != "0x70a08231".
  
  //taint source污点源的定义，这几种函数调用的返回值，一般认为是source源，被认为是攻击者可控的
.decl Leslie_FLTaintedVar(funcSign:symbol, var:Variable)
.output Leslie_FLTaintedVar
Leslie_FLTaintedVar(funcSign, var) :-
  CallToSignature(stmt, "getAmountsIn(uint256,address[])"), //"0x1f00ca74",
  ExternalCall_ActualReturn(stmt, var, _),
  Leslie_Statement_Function(stmt, func),
  PublicFunctionSelector(func, funcSign).

Leslie_FLTaintedVar(funcSign, var) :-
  CallToSignature(stmt, "getAmountsOut(uint256,address[])"), //"0xd06ca61f"
  ExternalCall_ActualReturn(stmt, var, _),
  Leslie_Statement_Function(stmt, func),
  PublicFunctionSelector(func, funcSign).

Leslie_FLTaintedVar(funcSign, var) :-
  CallToSignature(stmt, "balanceOf(address)"),
  ExternalCall_ActualReturn(stmt, var, 0),
  Leslie_Statement_Function(stmt, func),
  PublicFunctionSelector(func, funcSign).

// getreserves() in the victim's context tainted source
Leslie_FLTaintedVar(funcSign, var) :-
  CallToSignature(stmt, "getReserves()"),
  ExternalCall_ActualReturn(stmt, var, _),
  Leslie_Statement_Function(stmt, func),
  PublicFunctionSelector(func, funcSign).
  
.decl Leslie_FLSensitiveVar(funcSign:symbol, amount:Variable)
Leslie_FLSensitiveVar(funcSign, amount) :- 
  Leslie_FLSensitiveCall(stmt, recipient, amount),
  //是否存在transfer这样的敏感调用
  (PublicFunctionArg(_, var, _);CALLER(_, var);ORIGIN(_, var)), // manipulated by the caller
  //找到被攻击者操控的变量
  DataFlows(var, recipient),
  //查看敏感操作与操控变量间是否有数据流，有的话，就认为tranfer的余额是一个敏感变量
  Leslie_Statement_Function(stmt, func),
  PublicFunctionSelector(func, funcSign).
  
//判断tranfer函数调用中是否包含敏感操作，这里找到对应的transfer函数调用，并找到对应的接收者
.decl Leslie_FLSensitiveCall(callStmt:Statement, var:Variable, target:Variable)
.output Leslie_FLSensitiveCall
Leslie_FLSensitiveCall(callStmt, recipient, amount) :-
  CallToSignature(callStmt, "transfer(address,uint256)"),
  StatementUsesMemory_ActualMemoryArg(callStmt, _, 1, recipient),
  StatementUsesMemory_ActualMemoryArg(callStmt, _, 2, amount).

```

- interprocedural_analysis:

```python
    pps_near_fl_source = self.get_pps_near_fl_source()
    pps_near_fl_sink = self.get_pps_near_fl_sink()
    self.attack_matrix["price_manipulation"] = (
        self.find_potential_price_manipulation_attack(
            pps_near_fl_source, pps_near_fl_sink
        )
    )

# trace vulnerable flashloan-related flow
# 保存相应的被taint source污染的函数返回值，以及调用参数对应的信息
def get_pps_near_fl_source(self):
    pps_near_source = []
    for key in self.contracts.keys():
        temp_caller = key.split("_")[0]
        temp_callsite = key.split("_")[1]
        temp_address = key.split("_")[2]
        temp_funcSign = key.split("_")[3]

        temp_indexes = self.get_fl_tainted_ret(temp_address, temp_funcSign)
        #  通过对应的合约地址和函数签名，获得函数中taint source污染的返回值，对应的返回值index
        if len(temp_indexes) > 0:
            for temp_index in temp_indexes:
                pps_near_source.append(
                    self.new_pp(
                        temp_caller,
                        temp_callsite,
                        temp_address,
                        temp_funcSign,
                        temp_index,
                        self.contracts[key].func_sign,
                        "func_ret",
                    )
                )
				#         找到程序当前的地址
                # log.info("found tainted ret in contract: " + temp_address)

        temp_call_args = self.get_fl_tainted_call_args(temp_address, temp_funcSign)
        # 找到对应的函数中，taint source污染的函数调用参数，保存对应的函数调用stmt和对应的参数index
        if len(temp_call_args) > 0:
            for temp_call_arg in temp_call_args:
                (
                    temp_external_call_caller,
                    temp_external_call_logic_addr,
                    temp_external_call_func_sign,
                ) = self.get_external_call_info(
                    temp_call_arg["callStmt"], self.contracts[key].external_calls
                )
                # 返回对应的外部调用信息
                pps_near_source.append(
                    self.new_pp(
                        temp_external_call_caller,
                        temp_call_arg["callStmt"],
                        temp_external_call_logic_addr,
                        temp_external_call_func_sign,
                        temp_call_arg["callArgIndex"],
                        self.contracts[key].func_sign,
                        "call_arg",
                    )
                )
                # 保存对应的污点污染的信息
                # log.info("found tainted call arg in contract: " + temp_address)
    log.info(pps_near_source)
    return pps_near_source

# 保存相应的受到sink传播影响的敏感操作
def get_pps_near_fl_sink(self):
    pps_near_sink = []
    known_args = {}
    for key in self.contracts.keys():
        temp_caller = key.split("_")[0]
        temp_callsite = key.split("_")[1]
        temp_address = key.split("_")[2]
        temp_funcSign = key.split("_")[3]
        # the function that sink site lies in
        temp_caller_funcSign = key.split("_")[4]
        # log.info(temp_caller_funcSign)
        # get the taint sink: function arguments of the call arg to callee address
        temp_call_args = self.fl_get_callsites_flow_to_sink(
            temp_address, temp_funcSign
        )
        # 找到对应的函数调用返回值的index，该函数返回值是与taint sink之间是可达的
        if len(temp_call_args) > 0:
            for temp_call_arg in temp_call_args:
                (
                    temp_external_call_caller,
                    temp_external_call_logic_addr,
                    temp_external_call_func_sign,
                ) = self.get_external_call_info(
                    temp_call_arg["callStmt"], self.contracts[key].external_calls
                )
                ## 返回对应外部调用的调用信息
                pps_near_sink.append(
                    self.new_pp(
                        temp_external_call_caller,
                        temp_call_arg["callStmt"],
                        temp_external_call_logic_addr,
                        temp_external_call_func_sign,
                        temp_call_arg["callRetIndex"],
                        # bug fixed
                        self.contracts[key].func_sign,
                        "func_ret",
                    )
                )
                # add a sink as the transfer target
                # target = self.get_sensitive_call_from_call_ret(
                #     temp_call_arg["callStmt"], temp_external_call_caller
                # )
                # known_args[temp_call_arg["callStmt"]] = (
                #     self.get_external_call_known_arg_info(
                #         temp_call_arg["callStmt"],
                #         self.contracts[key].external_calls,
                #     )[temp_call_arg["callStmt"]]
                # )

            # log.info("====sink====")
			##   找到对应污点sink，依赖的变量，其为外部可操控的函数调用返回值
            # notice: the 'caller_funcsign' is the function that call the victim to call the 'funcsign' in the attack contract
    log.info(pps_near_sink)
    # get the functions called by victim (possible)
    return pps_near_sink
```

得到了对应source所污染的函数参数和函数返回值，和sink所依赖的函数调用返回值，依据上述的source和sink，分析对应的rule：

```python
    def find_potential_price_manipulation_attack(self, source, sink):
        reachable = False
        is_pm_attack = False
        for pp1 in source:
            for pp2 in sink:
                if self.is_same(pp1, pp2):
                    reachable = True
                    is_pm_attack = True
                elif self.is_reachable(pp1, pp2):
                    reachable = True
                    is_pm_attack = True
        if is_pm_attack:
            log.info("price manipulation")
        return reachable
	# 如果source污染的函数返回值和sink敏感操作依赖的函数返回值为同一个变量
    def is_same(self, pp1, pp2):
        pp1_str = (
            pp1["caller"]
            + "_"
            + pp1["callsite"]
            + "_"
            + pp1["func_sign"]
            + "_"
            + str(pp1["index"])
            + "_"
            + pp1["type"]
            + "_"
            + pp1["caller_funcSign"]
        )
        pp2_str = (
            pp2["caller"]
            + "_"
            + pp2["callsite"]
            + "_"
            + pp2["func_sign"]
            + "_"
            + str(pp2["index"])
            + "_"
            + pp2["type"]
            + "_"
            + pp2["caller_funcSign"]
        )
        if pp1_str == pp2_str:
            return True
        else:
            return False
    
    def is_reachable(self, pp1, pp2):
        if self.is_same(pp1, pp2):
            return True
        pending = [pp1]
        while len(pending) > 0:
            temp_pp = pending.pop()
            for pp in self.transfer(temp_pp):
                ## 判断是否有tainted source到sink的路径
                if self.is_same(pp, pp2):
                    # log.info(pp)
                    # log.info(pp2)
                    return True
                else:
                    pending.append(pp)
        return False
```

下面介绍一下tainted source污点传播的过程

```python
def transfer(self, pp):
    # log.info(pp)
    next_pps = []
    # log.info(pp["caller_funcSign"])
    parent_contract = self.find_parent(
        pp["contract_addr"], pp["func_sign"], pp["caller"], pp["callsite"]
    )
    # 找到调用该合约的合约
    # log.info(parent_contract.logic_addr)
    # log.info(parent_contract.caller)
    # log.info(parent_contract.func_sign)
    try:
        child_contract = self.find_contract(
            pp["caller"],
            pp["callsite"],
            pp["contract_addr"],
            pp["func_sign"],
            pp["caller_funcSign"],
        )
        # log.info(child_contract.logic_addr)
        # log.info(child_contract.caller)
        # log.info(child_contract.func_sign)
    except Exception:
        return next_pps

    # apply spread transfer for func_ret and call_arg, respectively
    ## 如果污点传播的方式是通过函数的返回值
    ## 查看该函数作为调用返回值，能够传播到的函数返回值和调用参数
    if pp["type"] == "func_ret":
        if parent_contract is not None:
            indexes = self.spread_callRet_funcRet(
                pp["caller"], pp["callsite"], parent_contract.func_sign, pp["index"]
            )
            for index in indexes:
                next_pps.append(
                    self.new_pp(
                        parent_contract.caller,
                        parent_contract.call_site,
                        parent_contract.logic_addr,
                        parent_contract.func_sign,
                        index,
                        pp["caller_funcSign"],
                        "func_ret",
                    )
                )

        callArgs = self.spread_callRet_CallArg(
            pp["contract_addr"], pp["callsite"], pp["index"]
        )
        for callArg in callArgs:
            (
                temp_caller,
                temp_logic_addr,
                temp_func_sign,
            ) = self.get_external_call_info(
                callArg["callStmt"], child_contract.external_calls
            )
            next_pps.append(
                self.new_pp(
                    temp_caller,
                    callArg["callStmt"],
                    temp_logic_addr,
                    # temp func sign is the called function that lies in the attacker contract
                    temp_func_sign,
                    callArg["callArgIndex"],
                    # pp[func_sign] is the function that calls back to attacker contract
                    pp["func_sign"],
                    "call_arg",
                )
            )
            # log.info(next_pps)
	# 如果污点的传播方式是通过调用参数
    # 查看在被调用合约中的，通过函数参数传播到的调用参数，被调用对象，以及函数返回值
    if pp["type"] == "call_arg":
        callArgs = []
        # function arg to call arg and callee var
        callArgs += self.spread_funcArg_callArg(
            pp["contract_addr"], pp["func_sign"], pp["index"]
        )
        callArgs += self.spread_funcArg_callee(
            pp["contract_addr"], pp["func_sign"], pp["index"]
        )

        for callArg in callArgs:
            temp_result = self.get_external_call_info(
                callArg["callStmt"], child_contract.external_calls
            )
            # log.info(temp_result)
            if temp_result is not None:
                temp_caller, temp_logic_addr, temp_func_sign = temp_result
            else:
                continue
            next_pps.append(
                self.new_pp(
                    pp["contract_addr"],
                    callArg["callStmt"],
                    temp_logic_addr,
                    temp_func_sign,
                    callArg["callArgIndex"],
                    pp["func_sign"],
                    "call_arg",
                )
            )
            # log.info(next_pps)
        # the return index of the function call
        indexes = self.spread_funcArg_funcRet(
            pp["contract_addr"], pp["func_sign"], pp["index"]
        )
        for index in indexes:
            next_pps.append(
                self.new_pp(
                    pp["caller"],
                    pp["callsite"],
                    pp["contract_addr"],
                    pp["func_sign"],
                    index,
                    pp["caller_funcSign"],
                    "func_ret",
                )
            )
    return next_pps
```



































