from pyspark import SparkContext
from datetime import datetime


class Handle_Partition_By_spark:
    '''
        This is a class that handles the message types in the partitions
    '''
    def __init__(self, match, PrefixTreeMatch, SimpleLoopMatch, LCSMatch, addSeqToPrefixTree, getTemplate,
                 removeSeqFromPrefixTree):
        '''
        When using this class, the user needs to provide the corresponding pre-filtering method and matching method,
        including prefix tree matching and simple loop matching, while the matching method is LCS matching,
        and also needs to provide the method to extract the template from log tokens
        :param match: a methoed that defines how to use all of the match function
        :param PrefixTreeMatch:
        :param SimpleLoopMatch:
        :param LCSMatch:
        :param addSeqToPrefixTree:
        :param getTemplate:
        :param removeSeqFromPrefixTree:
        '''
        self._match = match
        self._PrefixTreeMatch = PrefixTreeMatch
        self._SimpleLoopMatch = SimpleLoopMatch
        self._LCSMatch = LCSMatch
        self._addSeqToPrefixTree = addSeqToPrefixTree
        self._getTemplate = getTemplate
        self._removeSeqFromPrefixTree = removeSeqFromPrefixTree

    def _reduce(self, partition, logObject):
        logObject = logObject.logClustL[0]
        max = len(logObject.logTemplate)
        self._match(logObject.logTemplate, logObject.logIDL[0], partition.rootNode, partition.logClustL, max)
        return partition

    def run(self, structure_log_info):
        sc = SparkContext('local', 'Handle_Partition_By_Spark')
        # sc = SparkContext('spark://192.168.100.120:7077', 'Handle_Partition_By_Spark')
        rdd = sc.parallelize(structure_log_info)
        rdd = rdd.reduceByKey(self._reduce)

        now = datetime.now()
        result = rdd.collect()
        now = datetime.now() - now
        print('the time of calculation')
        print(now)

        return result
