public class Stopwatch{
    //This class is used in CovertChannel.java to measure the time taken to execute the program. The time will be used to measure the bandwidth.
    private final long start;

    public Stopwatch() {
	start = System.currentTimeMillis();
    }

    public double elapsedTime(){
	long now = System.currentTimeMillis();
	return (now - start) / 1000.0;
    }

}
