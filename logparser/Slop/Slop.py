import re
import os
import numpy as np
import pandas as pd
import hashlib
from datetime import datetime
import Handle_Partition_By_Spark
from LCSObject import LCSObject
from Node import Node
from Partition import Partition


class LogParser:
    """
    日志分析器
    """

    def __init__(self, logname, log_format, indir='./', outdir='./result/', tau=0.5, rex=[]):
        """
        初始化日志分析器，用户必须提供结果输出的日志名，以及分析的日志的格式
        :param logname: 日志文件名
        :param log_format: 日志格式
        :param indir: 日志文件夹的路径
        :param outdir: 结果输出输出路径
        :param tau: 门限值参数
        :param rex: 预处理的正则表达式
        """
        self.path = indir
        self.logname = logname
        self.savePath = outdir
        self.tau = tau
        # self.format_rex为系统的日志格式标签，如hadoop为‘<Date> <Time> <Pid> <Level> <Component>: <Content>’
        # self.headers为系统日志格式的标签名
        self.headers, self.format_rex = self.__generate_logformat_regex(log_format)
        # 结构化后的日志信息（提取标签作为列名）
        self.df_log = pd.DataFrame()
        # 用户自定义的分隔符的正则表达式，用于预处理
        self.rex = rex
        # 当前最长的信息长度
        self.max = 1
        # 门限值的计算方式，True为线性，False为非线性
        self.is_linear = False
        # 前缀树根节点
        self.rootNode = Node()
        # 当前LogObject集合
        self.logClustL = []
        # 当前长度分组
        self.group = dict()

    # 计算门限值
    def __getThreshold(self, length, max):
        if not self.is_linear:
            T = 2.64
            w = length / max * T
            result = self.tau * length * np.tanh(w)
            return result
        else:
            return self.tau * length

    # 返回messageType，参数部分用*表示
    def _getTemplate(self, lcs, seq):
        retVal = []
        if not lcs:
            return retVal

        lcs = lcs[::-1]
        i = 0
        for token in seq:
            i += 1
            if token == lcs[-1]:
                retVal.append(token)
                lcs.pop()
            else:
                retVal.append('<*>')
            if not lcs:
                break
        if i < len(seq):
            retVal.append('<*>')

        return retVal

    # 返回LCS串
    def __LCS(self, seq1, seq2):
        """
        比较两个序列，提取LCS
        :param seq1:
        :param seq2:
        :return:  LCS集合
        """
        lengths = [[0 for j in range(len(seq2) + 1)] for i in range(len(seq1) + 1)]
        # row 0 and column 0 are initialized to 0 already
        for i in range(len(seq1)):
            for j in range(len(seq2)):
                if seq1[i] == seq2[j]:
                    lengths[i + 1][j + 1] = lengths[i][j] + 1
                else:
                    lengths[i + 1][j + 1] = max(lengths[i + 1][j], lengths[i][j + 1])

        # read the substring out from the matrix
        result = []
        lenOfSeq1, lenOfSeq2 = len(seq1), len(seq2)
        while lenOfSeq1 != 0 and lenOfSeq2 != 0:
            if lengths[lenOfSeq1][lenOfSeq2] == lengths[lenOfSeq1 - 1][lenOfSeq2]:
                lenOfSeq1 -= 1
            elif lengths[lenOfSeq1][lenOfSeq2] == lengths[lenOfSeq1][lenOfSeq2 - 1]:
                lenOfSeq2 -= 1
            else:
                assert seq1[lenOfSeq1 - 1] == seq2[lenOfSeq2 - 1]
                result.insert(0, seq1[lenOfSeq1 - 1])
                lenOfSeq1 -= 1
                lenOfSeq2 -= 1
        return result

    # 前缀树预过滤
    def _PrefixTreeMatch(self, parentn, seq, idx, max):
        """
        遍历前缀树，判断是否seq在前缀树中出现
        :param parentn:根节点
        :param seq: 待匹配字段
        :param idx: seq待匹配的起始字段下标
        :param max: 当前最大日志长度
        :return: 匹配的logObject
        """
        retLogClust = None
        length = len(seq)
        for i in range(idx, length):
            if seq[i] in parentn.childD:
                childn = parentn.childD[seq[i]]
                # logClust为当前Node对应的LCSObject
                # 当其为空时，代表当前路径表示的字符串不存在
                # 非空时，就判断长度是否大于门限值
                if childn.logClust is not None:
                    constLM = childn.logClust.constLogTemplate
                    if float(len(constLM)) >= self.__getThreshold(length, max):
                        return childn.logClust
                else:
                    return self._PrefixTreeMatch(childn, seq, i + 1, length)

        return retLogClust

    # 简单循环预过滤
    def _SimpleLoopMatch(self, logClustL, seq, max):
        """
        将seq与logClustL中的所有日志模板进行简单匹配，只考虑模板信息是否在seq中出现，不考虑该模板是否是匹配最优的模板
        :param logClustL: logObject集合
        :param seq: 待匹配的序列
        :param max: 当前最大的日志长度
        :return: 匹配结果
        """
        retLogClust = None

        for logClust in logClustL:
            if float(len(logClust.logTemplate)) < self.__getThreshold(len(seq), max):
                continue

            q = 0
            p = 0
            # 逐个比对，如果比对结束后，模板的下标走到了最后，那就代表匹配成功
            while p < len(seq) and q < len(logClust.constLogTemplate):
                if seq[p] == logClust.constLogTemplate[q]:
                    q += 1
                p += 1
            if q == len(logClust.constLogTemplate):
                return logClust

        return retLogClust

    # LCS匹配
    def _LCSMatch(self, logClustL, seq, max):
        """
        与所有已知的messageType进行LCS匹配,返回匹配的logObject
        :param logClustL: logObject集合
        :param seq: 待匹配的序列
        :param max: 当前最大的日志长度
        :return:  匹配结果
        """
        retTemplate = None
        matchObject = None

        maxLen = -1
        maxlcs = []
        maxLCSObject = None
        set_seq = set(seq)
        size_seq = len(seq)
        # 遍历messageType，取最长的LCS作为messageType。多组LCS长度相同时，取最短的messageType（LCS在其内部比例更高）
        for LCSObject in logClustL:
            set_template = set(LCSObject.logTemplate)
            if len(set_seq & set_template) < self.__getThreshold(size_seq, max):
                continue
            lcs = self.__LCS(seq, LCSObject.logTemplate)
            if len(lcs) > maxLen or (len(lcs) == maxLen and len(LCSObject.logTemplate) < len(maxlcs)):
                maxLen = len(lcs)
                maxlcs = lcs
                maxLCSObject = LCSObject

        # 与门限值比较
        if float(maxLen) >= self.__getThreshold(size_seq, max):
            retTemplate = maxlcs
            matchObject = maxLCSObject
        return retTemplate, matchObject

    # 组内匹配
    def __partitionMatch(self, logmessageL, logID):
        """
        将logmessageL与对应分组的日志类型进行LCS匹配比较
        :param logmessageL: 待匹配的日志信息
        :param logID: 日志ID
        :return: 匹配结果
        """
        length = len(logmessageL)
        LCSClust = None
        # 如果该长度的模板并未创建分组，则直接创建分组
        if length not in self.group:
            # 如果进行读取训练结果的操作，那么此时的logmessageL是以前训练的日志模板，不存有ID，以负数表示
            if logID > 0:
                LCSClust = LCSObject(logmessageL, [logID], [s for s in logmessageL if s != '<*>'])
            else:
                LCSClust = LCSObject(logmessageL, [], [s for s in logmessageL if s != '<*>'])
            LCSClustL = [LCSClust]
            self.group[length] = Partition(LCSClustL)
        # 如果已存在该长度的分组，那么就在组内进行匹配
        else:
            LCS, matchObject = self._LCSMatch(self.group[length].logClustL, logmessageL, self.max)
            # 匹配失败则添加新模板
            if not LCS:
                if logID > 0:
                    LCSClust = LCSObject(logmessageL, [logID], [s for s in logmessageL if s != '<*>'])
                else:
                    LCSClust = LCSObject(logmessageL, [], [s for s in logmessageL if s != '<*>'])
                self.group[length].logClustL.append(LCSClust)
            # 匹配成功则取LCS为新的模板，删除原模板的信息，在merge阶段决定是否添加
            else:
                template = self._getTemplate(LCS, logmessageL)
                if ' '.join(matchObject.logTemplate) != ' '.join(template):
                    LCSClust = matchObject
                    matchObject.logTemplate = template
                    matchObject.constLogTemplate = [s for s in template if s != '<*>']
                    if logID > 0:
                        matchObject.logIDL.append(logID)
                    if matchObject in self.logClustL:
                        self.logClustL.remove(matchObject)
                    self._removeSeqFromPrefixTree(self.rootNode, matchObject)

        return LCSClust

    # 组间合并
    def __partitionMerge(self, LCSClust):
        """
        将组间匹配后的logObject与目前提取出的所有日志模板进行匹配，判断是否有子集关系，如果有，只保留子集
        :param LCSClust: 待合并的logObject
        :return: 是否有子集关系
        """
        isSub = False
        constLogTemplate2 = LCSClust.constLogTemplate

        for logObject in self.logClustL:
            constLogTemplate1 = logObject.constLogTemplate
            change = False
            # 永远让constLogTemplate2是短的序列
            if len(constLogTemplate1) < len(constLogTemplate2):
                temp = constLogTemplate1
                constLogTemplate1 = constLogTemplate2
                constLogTemplate2 = temp
                change = True
            # 如果LCS和短的序列相等，那么就存在子集关系
            if self.__LCS(constLogTemplate1, constLogTemplate2) == constLogTemplate2:
                # constLogTemplate2为新模板，所以新模板是原模板的子集，替换模板并增加序号
                if not change:
                    for id in logObject.logIDL:
                        LCSClust.logIDL.append(id)
                    self._removeSeqFromPrefixTree(self.rootNode, logObject)
                    self.logClustL.remove(logObject)
                    self.logClustL.append(LCSClust)
                    self._addSeqToPrefixTree(self.rootNode, LCSClust)
                # constLogTemplate2为原模板，所以原模板是新模板的子集，则仅增加序号
                else:
                    for id in LCSClust.logIDL:
                        logObject.logIDL.append(id)
                isSub = True
                break
            else:
                if change:
                    constLogTemplate2 = constLogTemplate1

        # 若不存在子集关系，则新创建LCSObject，并加入logClusterL中
        if not isSub:
            self.logClustL.append(LCSClust)
            self._addSeqToPrefixTree(self.rootNode, LCSClust)
        return isSub

    def _addSeqToPrefixTree(self, rootn, newCluster):
        """
        把logObject加到相应的结点上
        :param rootn: 根节点
        :param newCluster:需要加入的logObject
        :return:
        """
        parentn = rootn
        seq = newCluster.constLogTemplate

        for i in range(len(seq)):
            tokenInSeq = seq[i]
            # Match
            if tokenInSeq in parentn.childD:
                parentn.childD[tokenInSeq].templateNo += 1
            # Do not Match
            else:
                parentn.childD[tokenInSeq] = Node(token=tokenInSeq, templateNo=1)
            parentn = parentn.childD[tokenInSeq]

        if parentn.logClust is None:
            parentn.logClust = newCluster

    def _removeSeqFromPrefixTree(self, rootn, newCluster):
        parentn = rootn
        seq = newCluster.constLogTemplate

        for tokenInSeq in seq:
            if tokenInSeq in parentn.childD:
                matchedNode = parentn.childD[tokenInSeq]
                if matchedNode.templateNo == 1:
                    del parentn.childD[tokenInSeq]
                    break
                else:
                    matchedNode.templateNo -= 1
                    parentn = matchedNode
            else:
                break

    def _printTree(self, node, dep):
        pStr = ''
        for i in range(dep):
            pStr += '\t'

        if node.token == '':
            pStr += 'Root'
        else:
            pStr += node.token
            if node.logClust is not None:
                pStr += '-->' + ' '.join(node.logClust.logTemplate)
        print(pStr + ' (' + str(node.templateNo) + ')')

        for child in node.childD:
            self._printTree(node.childD[child], dep + 1)

    def parse_by_streaming(self, message, isFile=True):
        starttime = datetime.now()
        count = 0
        if isFile:
            print('Parsing file: ' + os.path.join(self.path, message))
            start, end = self.__load_file_by_streaming(message)
        else:
            self.df_log = self._log_join_dataframe(message, self.df_log, self.headers, self.format_rex)
            end = self.df_log.shape[0]
            start = end - 1
        if end == 0:
            return
        for idx, line in self.df_log[start:end].iterrows():
            # 设置编号与提取信息，提取依据为空格、'='、'：'和'，'
            logID = line['LineId']
            logmessageL = list(filter(lambda x: x != '', re.split(r'[\s=:,]', self._preprocess(line['Content']))))
            if len(logmessageL) > self.max:
                self.max = len(logmessageL)
            self._match(logmessageL, logID, self.rootNode, self.logClustL, self.max)

            count += 1
            if count % 1110000 == 0 or count == len(self.df_log[start:end]):
                print('Processed {0:.1f}% of log lines.'.format(count * 100.0 / len(self.df_log)))

        time = datetime.now() - starttime
        print('Parsing done. [Time taken: {!s}]'.format(time))

        return time.total_seconds()

    def parse_by_Spark(self, logname):
        print('Parsing file: ' + os.path.join(self.path, logname))
        starttime = datetime.now()
        self.__extract_template_by_Spark(logname)
        time = datetime.now() - starttime
        print('Parsing done. [Time taken: {!s}]'.format(time))
        return time.total_seconds()

    def _match(self, logmessageL, logID, rootNode, logClustL, maxLog):
        constLogMessL = [w for w in logmessageL if w != '<*>']
        matchCluster = self._PrefixTreeMatch(rootNode, constLogMessL, 0, maxLog)
        # 当前日志的messageType不存在于前缀树
        if matchCluster is None:
            matchCluster = self._SimpleLoopMatch(logClustL, constLogMessL, maxLog)
            # 当前日志的messageType不存在于已知messageType集合中，将其和当前所有messageType计算LCS
            if matchCluster is None:
                # 组内进行匹配，匹配成功则取LCS为新的模板，匹配失败则添加新模板
                LCS, matchObject = self._LCSMatch(logClustL, logmessageL, maxLog)
                if not LCS:
                    LCSClust = LCSObject(logmessageL, [logID], [s for s in logmessageL if s != '<*>'])
                    logClustL.append(LCSClust)
                    self._addSeqToPrefixTree(rootNode, LCSClust)
                else:
                    template = self._getTemplate(LCS, logmessageL)
                    if ' '.join(matchObject.logTemplate) != ' '.join(template):
                        matchObject.logTemplate = template
                        matchObject.constLogTemplate = [s for s in template if s != '<*>']
                        matchObject.logIDL.append(logID)
                        self._removeSeqFromPrefixTree(rootNode, matchObject)
                        self._addSeqToPrefixTree(rootNode, matchObject)
        if matchCluster:
            matchCluster.logIDL.append(logID)

    # 读取日志信息，建立df_log
    def __load_file_by_streaming(self, logname):
        start, end = self.__log_to_dataframe(os.path.join(self.path, logname))
        return start, end

    def __extract_template_by_Spark(self, logname):
        structure_log_info = self.get_log_info(os.path.join(self.path, logname))
        # 传参进行运行
        handle = Handle_Partition_By_Spark.Handle_Partition_By_spark(self._match, self._PrefixTreeMatch,
                                                                     self._SimpleLoopMatch
                                                                     , self._LCSMatch, self._addSeqToPrefixTree,
                                                                     self._getTemplate, self._removeSeqFromPrefixTree)

        reduce_result = handle.run(structure_log_info)
        for message in reduce_result:
            length = message[0]
            partition = message[1]
            self.group[length] = partition

        for length in self.group:
            for logCluster in self.group[length].logClustL:
                self.__partitionMerge(logCluster)

    # 读取日志训练信息，在清空LCSObject序号关系后，将读取的信息并入当前训练结果中
    def __load_data(self):
        import pickle
        with open(os.path.join(self.savePath, self.logname + "_group.txt"), "rb") as f:
            group = pickle.load(f)
            for length in group:
                if length not in self.group:
                    self.group[length] = group[length]
                for logClust in group[length].logClustL:
                    o = self.__partitionMatch(logClust.constLogTemplate, -1)
                    if o is not None:
                        self.__partitionMerge(o)
        return

    def __getParameter(self, template, seq):
        retVal = []
        t_index = 0
        s_index = 0
        logmessageL = list(filter(lambda x: x != '', re.split(r'[\s=:,]', seq)))

        while t_index < len(template) and s_index < len(logmessageL):
            if template[t_index] == '<*>':
                retVal.append([logmessageL[s_index].strip('/').strip('\\')])
            t_index += 1
            s_index += 1

        return retVal

    # 输出结果文件
    def outputResult(self):
        if not os.path.exists(self.savePath):
            os.makedirs(self.savePath)
        templates = [0] * self.df_log.shape[0]
        ids = [0] * self.df_log.shape[0]
        parameter = [0] * self.df_log.shape[0]
        df_event = []

        for logclust in self.logClustL:
            if len(logclust.logIDL) == 0:
                continue
            template_str = ' '.join(logclust.logTemplate)
            eid = hashlib.md5(template_str.encode('utf-8')).hexdigest()[0:8]
            empty = True
            for logid in logclust.logIDL:
                if logid > 0:
                    empty = False
                    templates[logid - 1] = template_str
                    ids[logid - 1] = eid
                    if self.df_log.loc[logid - 1, 'LineId'] == logid:
                        para = self.__getParameter(logclust.logTemplate, self.df_log.loc[logid - 1, 'Content'])
                        parameter[logid - 1] = para
                    else:
                        for idx, line in self.df_log.iterrows():
                            if line['LineId'] == logid:
                                para = self.getParameter(logclust.logTemplate, self.df_log.loc[logid - 1, 'Content'])
                                parameter[logid - 1] = para
                                break
            if empty:
                continue
            df_event.append([eid, template_str, len(logclust.logIDL)])

        df_event = pd.DataFrame(df_event, columns=['EventId', 'EventTemplate', 'Occurrences'])

        self.df_log['EventId'] = ids
        self.df_log['EventTemplate'] = templates
        self.df_log['Parameter'] = parameter
        self.df_log.to_csv(os.path.join(self.savePath, self.logname + '_structured.csv'), index=False)
        df_event.to_csv(os.path.join(self.savePath, self.logname + '_templates.csv'), index=False)

    # 输出训练结果
    def outputData(self):
        import pickle
        with open(os.path.join(self.savePath, self.logname + "_group.txt"), "wb") as f:
            pickle.dump(self.group, f)
        return

    # 根据初始自定义的正则表达式来格式化日志，把对应部分变为*
    def _preprocess(self, line):
        for currentRex in self.rex:
            line = re.sub(currentRex, '<*>', line)
        return line

    def _log_join_dataframe(self, message, df_log, headers, format_rex):
        log_messages = []
        start = df_log.shape[0]
        end = start

        message = re.sub(r'[^\x00-\x7F]+', '<NASCII>', message)
        match = format_rex.search(message.strip())
        message = [match.group(header) for header in headers]
        log_messages.append(message)
        end += 1

        logdf = pd.DataFrame(log_messages, columns=headers)
        logdf.insert(0, 'LineId', None)
        logdf['LineId'] = [i + 1 for i in range(start, end)]
        if not df_log.empty:
            df_log = df_log.append(logdf, ignore_index=True)
        else:
            df_log = logdf
        return df_log

    def get_log_info(self, log_file):
        log_messages = []
        structure_log_info = []
        if self.df_log.empty:
            start = 0
            end = 0
        else:
            start = self.df_log.shape[0]
            end = start
        count = 0
        now = datetime.now()
        with open(log_file, 'r') as fin:
            for line in fin.readlines():
                # 把非ASCII码信息替换为<NASCII>标签
                line = re.sub(r'[^\x00-\x7F]+', '<NASCII>', line)
                # 把标签外的日志信息提取出来
                try:
                    end += 1
                    match = self.format_rex.search(line.strip())
                    # match.group(header),可按之前正则表达式中的命名进行分组
                    message = [match.group(header) for header in self.headers]
                    log_messages.append(message)

                    content = list(filter(lambda x: x != '', re.split(r'[\s=:,]',
                                                                      self._preprocess(match.group('Content')))))
                    lineId = end
                    length = len(content)
                    # 每个info可看做一个分区
                    info = Partition(logClustL=[])
                    info.rootNode = Node()
                    info.logClustL.append(LCSObject(logTemplate=content, logIDL=[lineId], constLogTemplate=content))
                    self._addSeqToPrefixTree(info.rootNode, info.logClustL[0])
                    partition = (length, info)
                    structure_log_info.append(partition)

                    count += 1
                    if count % 100000 == 0:
                        print(count)
                        print(datetime.now() - now)
                        now = datetime.now()
                except Exception as e:
                    # print("抛出异常: "+str(e))
                    pass
        logdf = pd.DataFrame(log_messages, columns=self.headers)
        logdf.insert(0, 'LineId', None)
        logdf['LineId'] = [i + 1 for i in range(start, end)]
        if not self.df_log.empty:
            self.df_log = self.df_log.append(logdf, ignore_index=True)
        else:
            self.df_log = logdf
        return structure_log_info

    # 为日志建立dataFrame，把日志格式标签作为列名，并从数据中提取对应信息放入列中
    def __log_to_dataframe(self, log_file):
        """ Function to transform log file to dataframe
        """
        now = datetime.now()
        log_messages = []
        count = 0
        if self.df_log.empty:
            start = 0
            end = 0
        else:
            start = self.df_log.shape[0]
            end = start
        with open(log_file, 'r') as fin:
            for line in fin.readlines():
                # 把非ASCII码信息替换为<NASCII>标签
                line = re.sub(r'[^\x00-\x7F]+', '<NASCII>', line)
                # 把标签外的日志信息提取出来
                try:
                    match = self.format_rex.search(line.strip())
                    # match.group(header),可按之前正则表达式中的命名进行分组
                    message = [match.group(header) for header in self.headers]
                    log_messages.append(message)
                    end += 1
                    count += 1

                    if count % 4000000 == 0:
                        print(count)

                except Exception as e:
                    # print("抛出异常: "+str(e))
                    pass
        logdf = pd.DataFrame(log_messages, columns=self.headers)
        logdf.insert(0, 'LineId', None)
        logdf['LineId'] = [i + 1 for i in range(start, end)]
        if not self.df_log.empty:
            self.df_log = self.df_log.append(logdf, ignore_index=True)
        else:
            self.df_log = logdf

        now = datetime.now() - now
        print('pre is ' + str(now))
        return start, end

    # 建立处理格式标签信息的正则表达式
    def __generate_logformat_regex(self, logformat):
        """ Function to generate regular expression to split log messages
        """
        headers = []
        # 把<标签>分隔开
        splitters = re.split(r'(<[^<>]+>)', logformat)
        regex = ''
        for k in range(len(splitters)):
            # 把空格替换为\s+
            if k % 2 == 0:
                splitter = re.sub(' +', '\s+', splitters[k])
                regex += splitter
            # 把标签替换为(?P<标签>.*?)
            else:
                header = splitters[k].strip('<').strip('>')
                # (?p<标签>...)是分组命名的意思，给...命名为<标签>  .*?则为懒惰型匹配
                regex += '(?P<%s>.*?)' % header
                headers.append(header)
        regex = re.compile('^' + regex + '$')
        return headers, regex
