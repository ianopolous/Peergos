package peergos.server.cli;

import java.io.PrintWriter;
import java.util.concurrent.atomic.AtomicLong;

public class ProgressBar implements Runnable {

    private static final String[] ANIM = new String[]{"|", "/", "-", "\\"};

    private static final int DEFAULT_PROGRESS_BAR_LENGTH = 20;
    private static final int DEFAULT_TICK_LENGTH_MILLIS = 250;

    private AtomicLong accumulatedBytes = new AtomicLong();
    private final Thread runner;
    private final long tickLengthMillis;
    private final long totalSize;
    private final int progressBarLength;

    private volatile boolean isFinsished, isStarted;
    private int animationPosition;
    //guarded by this
    private PrintWriter writer;

    public ProgressBar(PrintWriter writer, long totalSize) {
        this(writer, totalSize, DEFAULT_PROGRESS_BAR_LENGTH, DEFAULT_TICK_LENGTH_MILLIS);;
    }

    public synchronized void start() {
        if  (this.isFinsished)
            throw new IllegalStateException();
        if (this.isStarted)
            throw new IllegalStateException();
        this.isStarted = true;
        runner.start();
    }

    public synchronized void join() {
        while (runner.isAlive())
            try {
                runner.join();
                return;
            } catch (InterruptedException ie) {}
    }

    public ProgressBar(PrintWriter writer, long totalSize, int progressBarLength, long tickLengthMillis) {
        this.writer = writer;
        this.tickLengthMillis = tickLengthMillis;
        this.totalSize = totalSize;
        this.progressBarLength = progressBarLength;
        this.runner = new Thread(this::run);
    }

    public void update(long update) {
        accumulatedBytes.addAndGet(update);
    }

    private String progressBar(long currentAccumulated) {
        double frac =  (double) currentAccumulated / (double) totalSize;
        int barsProgressed = (int) (frac * progressBarLength);

        StringBuilder sb = new StringBuilder();
        sb.append('[');
        for (int i = 0; i < progressBarLength; i++) {
            if (i <= barsProgressed)
                sb.append('=');
            else
                sb.append(' ');
        }
        sb.append(']');
        return sb.toString();
    }

    private String format(boolean isUpdated,  long currentAccumumated) {
        StringBuilder sb =  new StringBuilder("\r");
        sb.append(getAnimation(isUpdated));
        sb.append("\t");
        sb.append(progressBar(currentAccumumated));
        sb.append("\t");
        return sb.toString();

    }

    private String getAnimation(boolean update) {
        if (update)
            animationPosition++;
        return ANIM[animationPosition % ANIM.length];
    }

    /**
     *
     * @return  current accumulated total.
     */
    private long tick(long previousAccumulated) {
        long currentAccumulated = accumulatedBytes.get();
        boolean isUpdated = currentAccumulated != previousAccumulated;
        String msg = format(isUpdated, currentAccumulated);
        writer.print(msg);

        if (currentAccumulated >= totalSize) {
            isFinsished = true;
            writer.println();
        }
        writer.flush();
        return currentAccumulated;
    }

    @Override
    public void run() {
        long previousAcc = 0;
        do {
            long currentAcc = tick(previousAcc);
            previousAcc = currentAcc;
            try {
                Thread.sleep(tickLengthMillis);
            } catch (InterruptedException ie) {}

        } while  (! isFinsished);
    }

    public static void main(String[] args) throws Exception {

        int total = 1000;
        ProgressBar progressBar = new ProgressBar(new PrintWriter(System.out), total);
        progressBar.start();
        for (int i = 0; i < total; i++) {
            progressBar.update(10);
            Thread.sleep(250);
        }
        progressBar.join();
    }
}
