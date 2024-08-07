---
title: Paper summary
date: 2023-12-15 22:24:25
---

## eTainter: detecting gas-related vulnerabilities in smart contracts--ISSTA2022

- 问题：智能合约代码中可能包含的gas-related vulnerabilities，具体来说包含两种，一是unbound loop,循环无界，导致的超过block gas的限制，二是Dos with failed call，循环中包含许多外部调用，一个抛出就导致全部revert。
- 事前对智能合约代码进行审计，属于事前智能合约漏洞审计
- 解决方法和思想：认为这些gas-releated漏洞的真正原因是，其中一些步骤攻击者可控，故采用污点分析

针对两种漏洞：污点source ：(data loaded from storage slots written or manipulated by contract users)  污点sink：循环的条件和循环体中函数调用的目标地址（if the return of the call is the condition of a revert statement in the loop’s body）。重点介绍了污点传播的方法，在合约storage和memory中传播的思路，以及如何减少误报和漏洞的策略

- Evaluation：1. 已有工具对比，2. overhead，  3.real-world contracts

## Toward Automated Detecting Unanticipated Price Feed in Smart Contract--ISSTA2023

- 问题：区块链价格预言机导致的异常价格喂价安全问题，将价格预言机分为DON，DEX，internal三种分别阐述对应的预言机特点，异常价格喂价的原因不单单是由合约代码导致，VeriOracle将合约源码和交易序列结合进行分析
- 实时地对区块链交易进行检测，属于智能合约异常价格喂价实时监测
- 解决方法和思想：（不是很了解）利用形式化的方法对整个交易过程进行建模，相当于给每个地址和预言机维护状态，交易通过相应的状态机改变对应的状态，形式化验证的方法
- Evaluation：1.已有的13个Defi事件进行分析，2.时间和空间效率的验证，能否支持实时监测，3.能够扩展至防护验证的尝试

## ISSTA- Access control

- 问题：区块链智能合约中的access control漏洞，如何实现有效检测，与finding permission bugs是同样的问题，已有的方法存在静态范式定义和交易历史较少的问题
- 事前对智能合约代码进行审计，属于事前智能合约漏洞审计
- 解决方法和思想：通过图相似度的比较，在**文章中收集了大量审计报告的合约，我们认为其为高质量合约集，没有漏洞的，对检测合约进行相应的相似度匹配，具体来说，流程如下：
  - 对函数进行相应提取，提取改变状态变量和，并且外部可调用函数，根据签名和函数在高质量数据库中匹配
  - 构建相应的ACFG图，先对函数中不重要的语句进行剪枝，后对函数中不同的语句形式进行一个归一化处理，并嵌入ACFG图
  - 最后利用二分图算法进行相似度的比较，并进行一个打分机制，来去除噪声的影响
- Evaluation：1.smartbugs数据集上检测效果测试，2.与state-of-the-art工具进行对比，3.消融实验

## SmartState: Detecting State-Reverting Vulnerabilities in Smart Contracts via Fine-Grained State-Dependency Analysis--ISSTA2023

- 问题：定义了智能合约中的一类问题，state-revert vulnerabilities漏洞，现有的研究都只包含一部分的漏洞，这篇文章主要针对SRV的两种场景，都是state-revert控制语句导致的（require，assert等），profit-gain和Deny-of-service两种情况，ISSTA2022的etainter就针对一部分gas-related的DOS攻击
- 也是属于事前对智能合约代码进行审计，但用到了历史交易的信息。
- 解决方法和思想：构建细粒度的状态依赖图，并定义相应的SRV indicators，后利用污点分析确定相应的漏洞代码，具体流程如下：
  - 利用已有的静态分析工具，得到合约的控制流信息，以及基本的read&write等依赖信息
  - 定义了两种状态依赖的关系，ASD和TSD，断言状态依赖应该比较好确定，时序状态依赖是通过交易历史进行构建（但构建方法比较简单，描述的很复杂）
  - 定义两类漏洞的范式，进行相应的图查找，判断是否存在SRV indicator
  - 进行污点分析，判断相应的状态变量，是否存在路径外部可控
  - 进行状态依赖的前向分析，判断哪些状态变量会收到影响。
- Evaluation：1. 在收集的SRV数据集上进行相应的测试，2. 消融实验，ASD和TSD依赖关系的影响，3. 与state-of-the-art工具进行对比，4. large-scale数据集上的测试。

## ISSTA- Read-Only Reentrancy

- 问题：新型重入漏洞，Read-only Reentrancy漏洞，是指攻击者调用一个DApp的合约，操纵了某种状态，随后回调到攻击者，这时攻击者进入另一个DApp进行相应操作（该操作一定程度上依赖于前述状态），这时攻击者产生获利，跟价格操纵攻击有点重叠

- 事前对智能合约代码进行审计
- 解决方法：构建大规模的DApp数据库，进行细粒度的上下文分析，进行跨DApp的静态分析，构建合约之间的依赖关系，寻找entry point入口点，通过Fuzz进行相应的ROR的验证，路径满足相应的条件。
  - 提出了一种根据DApp builder划分DApp的方法，获得了DApp的数据集
  - 在ItyFuzz的基础上，重放交易，获得细粒度的上下文关系
  - 在slither基础上，执行细粒度的静态分析，建立对应流图，寻找可能的entry point
  - 进行相应的fuzz，路径验证判断是否为ROR
- Evaluation:  1. 收集的几十个ROR上测试， 2. 消融实验，重放交易、跨DApp静态分析, 多函数fuzz的影响，3.与现有的ityFuzz Sailfish进行对比

## ISSTA- Centralization Defects

- 问题：中心化缺陷问题，主要针对项目的创建者来说，这个项目的一些逻辑存不存在中心化的问题，根据已有的报告划分了七大类中心化缺陷，都比较常见。
- 事前对智能合约的项目代码进行审计
- 解决方法：静态分析，得到数据流关系，后计算语义senmatic特征和权限permission特征，预定义七类中心化缺陷的检测规则，就利用slither，然后定义规则，很简单，重要工作在前面的缺陷定义和数据集的收集吧
- Evaluation：1. 在已有的30多万合约上进行检测， 2. 人工抽样检测对应的误报和漏报，给出每种的具体原因，单独的一章Discussion，讨论case study, defects定义，可能的解决措施。

## ISSTA- Price manipulation

- 问题：价格操纵攻击的检测，与Defitainter一致，但这篇文章主要是从交易的行为的角度对价格操纵攻击进行检测
- 支持实时对价格操纵攻击进行检测，并具有一定的分析结果（只能帮助安全审计师），无法真正实现提前预警
- 解决方法：对区块链中价格操纵进行相应的建模，随后链上实时监控，如果发现了代币价格变化超出阈值，并且获得了利润则认为存在价格操纵攻击发生，并对该过程的可疑地址和资金流以及函数调用关系进行分析
  - 对价格操纵攻击各个过程进行状态机建模，normal、abnormal、price read、profit等
  - 将各种主流的Defi主流项目的价格计算协议融入到Defort的价格计算机制中，对Defi项目利用字节码相似度比较，签名库匹配对应的价格计算函数签名，确定价格计算机制，并定义相应的阈值，若代币比率超过阈值，状态机变为abnormal状态，计算模型转换到异常状态后所有与 DeFi 应用交互的账户的利润。判断获利的过程。
  - 在检测过程中，记录相应的可疑地址、资金流关系以及函数调用，便于对该价格操纵事件进行全面的分析和认识。
- Evaluation:  1. 收集了主流的500多个Defi，进行攻击检测精度和误报率的测试，分析对应的原因，2. 对Defort的关键函数，资金流的分析结果，结合web3安全公司报告进行分析，3.实时检测相应的价格操纵攻击，并对相应的原因进行分析

## GPTScan: Detecting Logic Vulnerabilities in Smart Contracts by Combining GPT with Program Analysis--ICSE2024

- 问题：针对逻辑相关的漏洞检测，划分了十类漏洞，包括front-running、price manipulation以及access control等相关的，比较零散，统一归结定义为一类逻辑漏洞--logic vulnerabilities
- 事前对智能合约进行审计分析，判断有没有漏洞
- 解决方法：首先是依据静态分析技术对智能合约以及函数进行删选，找出可疑的函数及其依赖相关的函数；随后对其定义的十种漏洞类型，进行场景和漏洞范式的具体定义，随后可疑的关键变量和状态交给静态分析模块进行漏洞的确认
  - 函数过滤模块：先将不必要的文件和函数去除，对openzeppelin的标准函数进行匹配，作为白名单，函数可达性的分析与判断
  - 基于GPT的场景和范式匹配：对每种漏洞进行发生场景和漏洞范式的描述，利用GPT进行相应匹配
  - 静态分析对漏洞的确认过程没有详细说明，只是要求GPT对关键变量和函数进行回答，并设计四种规则进行检查。
- Evaluation：在Top200、web3Bugs以及Defihacks上进行实验。1. 三个数据中的误报；2. 检测结果的准确率；3. 消融实验，静态分析结果减少了多少误报；4. 漏洞检测的速度以及相应的开销；5. web3Bugs中真实发现的漏洞

## LookAhead: Preventing DeFi Attacks via Unveiling Adversarial Contracts -- arxiv

- 问题：对区块链中攻击者部署的攻击合约，利用监督机器学习方法进行检测，提前识别攻击活跃，进行预警
- 实时对攻击者部署的攻击合约进行检测，但是应该没有做到实时监测的能力和效果
- 解决方法：依据对攻击合约和正常合约的观察，定义了六大类特征，每类特征的定义都有相应的统计数据支撑，依据RPC、Explorer以及decompilation三种方式获取合约的特征数据，随后构建分类器，训练多种机器学习模型，进行比较
- Evaluation：1. 在测试集的数据上，对合约检测的精度、召回率以及误报率进行统计分析；2. 将定义的特征划分为两大类，进行特征的消融实验，说明特征的有效性；3. 错误分析：对漏报和误报的案例进行分析和说明
- 思考：无法实现检测的实时性，这是一个劣势，同时没有后续的分析，无法说明检测结果的可信性

## 下面是关于图学习的方法来解决智能合约漏洞检测的调研

## Smart Contract Vulnerability Detection Using Graph Neural Networks -- IJCAI2020

- 问题：之前的智能合约漏洞检测方案依赖于固定了专家模式，导致检测准确率较低，想利用图神经网络进行智能合约漏洞的检测，主要针对三种漏洞：重入、时间戳依赖和无限循环漏洞
- 解决方法：划分三类节点，构建节点连接图，捕获节点间的语义依赖关系，构建相应的连接边，并提出一种节点消除过程规范化连接图，并且提出一种时序信息传播网络，进行智能合约漏洞检测
- Evaluation：
  - dataset: 两个平台上5w个合约
  - 1. 与程序分析的sota方法进行比较，2. 与其它类型的神经网络进行比较，3. 探究了图规范化方法是否起作用
- 思考：重点关注图的构建和嵌入的过程，对智能合约进行静态解析，构建三种节点，四种边，设计图规范化方法对图进行归一化，只能对源码进行漏洞，这部分已经有很多的工作

## Combining Graph Neural Networks with Expert Knowledge for Smart Contract Vulnerability Detection -- TKDE2021（IJCAI2021）

- 在IJCAI2020的基础上做的，将图特征的提取建模与设计的专家模式相结合，进行漏洞检测

- 区别：将图神经网络和专家模式结合进行漏洞检测，对特定漏洞定义特定漏洞规则，并建模关键变量
- 解决方法：1. 安全模式的提取，对三种漏洞定义一些漏洞模式，2. 与IJCAI一致的图构建和规范化处理，3. 对专家模式进行FNN训练生成专家模式特征，结合图特征，进行特征融合传递到全连接层输出结果
- Evaluation：
  - dataset : 与IJCAI2020一致
  - 1. 与SOTA工具进行比较，2. 与已有的神经网络方法比较，3. 消融实验，图规范化处理、两种特征的消融对比实验，特征融合后的传播网络设置
- 思考：与IJCAI2020的工作改变不大，只是添加了专家模式特征提取的部分，进行了特征融合的操作，并且针对的漏洞类型也已经有了很多相关工作

## Hunting Vulnerable Smart Contracts via Graph Embedding Based Bytecode Matching -- TIFS2021

- 问题：现有方法的缺陷，利用与漏洞代码进行相似度的匹配来判断是否存在漏洞，存在两个挑战，一是不同版本的编译器编译出来的字节码可能不一致，二是相似度匹配过很多无用代码对结果产生干扰，也是针对常见的五种漏洞：溢出、重入、弱随机性、所有权未保护以及错误处理的抛出漏洞
- 解决方法：
  - 为解决第二个挑战，对代码进行切片，设计四类切片标准
  - 为解决第一个挑战，使用标准化技术处理切片片段，第一种建立数据标签作为操作数，第二种是统一调整操作数的顺序
  - 将代码切片转化成控制流图，参考Graph2Vec进行图嵌入，进行相似度比较实现漏洞检测
- Evaluation：
  - dataset：2m链上海量字节码合约、3w开源源代码合约，24个CVE漏洞合约
  - 检测时间的性能指标、检测的准确率
  - 对比消融实验，词袋模型进行嵌入、与SOTA一些检测方法比较，对切片和标准化两种技术进行消融实验
  - 对Honeypot这一类合约的检测能力
- 思考：从操作码序列的角度进行相似度比较，从而进行漏洞检测，也有一些类似的角度

## Cross-Modality Mutual Learning for Enhancing Smart Contract Vulnerability Detection on Bytecode -- WWW2023

- 问题：针对之前很多工作对源码进行漏洞检测，这些提出一种跨模态相互学习框架，针对字节码进行漏洞检测，也只主要关注四种漏洞：重入漏洞、时间戳依赖、整数溢出以及delegatecall
- 解决方法：
  - 代码语义建模的过程：对源码和字节码分别进行处理得到语义向量，源码利用TKDE2021中类似的方法，字节码生成控制流，微调BERT提取字节码块的特征，利用GAT生成高级图语义的嵌入
  - teacher-student 网络：设计源码和字节码结合的teacher网络，用以监督只有字节码的student网络的学习，使得student具有重建源码语义的能力
- Evaluation：
  - 收集了4w个有源代码和字节码的合约，并且经过手动标记
  - 先将该方法与传统SOTA和基于深度学习的方法进行了比较
  - 评估跨模态互学习的作用
  - 评估代码语义建模模块的作用：BERT字节码特征提取以及GAT高级图语义嵌入

## A vulnerability detection framework with enhanced graph feature learning -- The Journal of Systems & Software

- 问题：已有的图神经网络方法都只关注于学习本地节点，而忽略了全局节点信息，提出一种方法提取图结构中的全局节点信息，实现局部节点特征和全局节点信息融合的图特征实现漏洞检测
- 解决方法：
  - 对字节码构建相应的控制流图，利用word2vec对每个块进行编码，构建节点特征矩阵
  - 利用卷积运算捕获关键节点的特征，利用多头注意力机制捕获远程依赖构建，提取全局节点信息
  - 利用正常图神经网络提取局部节点特征，进行特征融合，实现漏洞检测
- Evaluation：
  - dataset：在WWW2023数据集基础上完成
  - 与程序分析的sota技术以及深度学习方法进行比较
  - 局部特征和全局特征的影响
  - 局部特征的神经网络和全局特征的神经网络选择对实验结果的影响

































