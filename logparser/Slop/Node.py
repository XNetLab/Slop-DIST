class Node:
    """
    前缀树的结点
    """

    def __init__(self, token='', templateNo=0):
        """

        :param token: 该节点表示的字符
        :param templateNo: 该节点及其子树中存有的模板数
        """
        # logClust为该点代表的LogObject
        self.logClust = None
        self.token = token
        # 该点及子节点可表示的模板数量
        self.templateNo = templateNo
        self.childD = dict()
    def __str__(self):
        return 'Node\'s children: ' + str(self.childD)
