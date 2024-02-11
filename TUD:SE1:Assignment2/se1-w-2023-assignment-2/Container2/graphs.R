library(lattice)

read.table("output-throughput-latency/stats.csv", header=TRUE) -> csvDataFrameSource
csvDataFrame <- csvDataFrameSource

trellis.device("pdf", file="graph1.pdf", color=T, width=6.5, height=5.0)

# ... xyplot here
xyplot(requests ~ rate, data = csvDataFrame, xlab="Requests", ylab="Throughput", type="b")

dev.off() -> null 

trellis.device("pdf", file="graph2.pdf", color=T, width=6.5, height=5.0)

# ... xyplot here
xyplot(latency ~ rate, data = csvDataFrame, xlab="Latency", ylab="Rate", type="b")

dev.off() -> null 
