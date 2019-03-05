class LCSObject:
    """
    存储相同模板的日志组
    """

    def __init__(self, logTemplate='', logIDL=[], constLogTemplate=''):
        """

        :param logTemplate: 日志模板，存放一组log token
        :param logIDL: 属于该模板的日志ID列表
        :param constLogTemplate: 日志模板的文字信息
        """
        self.logTemplate = logTemplate
        self.constLogTemplate = constLogTemplate
        self.logIDL = logIDL

    def __str__(self):
        t = ' '.join(self.logTemplate)

        id = ' '.join(str(self.logIDL))
        return "ID: " + id + ', template: ' + t