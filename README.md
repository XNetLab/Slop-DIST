<p align="center"> </p>


# Slop
Slop's relevant code is called by the slop_demo.py module, where the user enters the log path and slopping information to run the program.Moreover, the user can choose to use the distributed processing method or the streaming processing method. After the end of running, the program will automatically output the calculation time of the method to facilitate the user to compare the efficiency.At the same time, if the user needs, the outputResult() method can be used to output the extraction results of message types to verify the correctness of the algorithm.
Finally, if the user needs to use distributed processing, make sure that the spark environment is configured and that the connection to the cluster is set in the Handle_Partition_By_spark module.

### Acknowledgement
Slop is implemented based on a existing open-source projects:
+ [logparser](https://github.com/logpai/logparser(Python)
