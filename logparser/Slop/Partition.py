from Node import Node
class Partition:
    """
    标识一个分组，存储长度相同的LCSObject集合和相应的前缀树根节点
    """

    def __init__(self, logClustL=[]):
        """

        :param logClustL: 该模板存储的LCSObject集合
        """
        self.logClustL = logClustL
        self.rootNode = Node()

    def __str__(self):
        s = []
        for l in self.logClustL:
            s.append(str(l))
        ss = str(self.rootNode.childD)
        return 'Node\'s children:'+ ss + ' template list: ' + '\n'.join(s)
