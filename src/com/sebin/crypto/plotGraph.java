package com.sebin.crypto;

import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.jfree.chart.*;
import org.jfree.chart.axis.NumberAxis;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.chart.plot.XYPlot;
import org.jfree.chart.renderer.xy.XYLineAndShapeRenderer;
import org.jfree.chart.axis.LogarithmicAxis;
import org.jfree.data.xy.XYSeries;
import org.jfree.data.xy.XYSeriesCollection;
import org.jfree.ui.ApplicationFrame;

public class plotGraph  {
	public static void main(String[] args) throws IOException 
    {
		
		XYSeriesCollection dataset=new XYSeriesCollection();
		try {
			dataset = RSABouncyCastle.getDataset();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (InvalidCipherTextException e) {
			e.printStackTrace();
		}
        JFreeChart chart = ChartFactory.createXYLineChart(
            "Time Taken for RSA Operations vs Key Size",
            "Key Size (bits)",
            "Time Taken (Seconds)",
            dataset,
            PlotOrientation.VERTICAL,
            true,
            true,
            false
            );

        LogarithmicAxis yAxis = new LogarithmicAxis("Seconds");

        XYPlot plot = chart.getXYPlot();
        plot.setRangeAxis(yAxis);

        XYLineAndShapeRenderer renderer = (XYLineAndShapeRenderer)plot.getRenderer();
        renderer.setSeriesShapesVisible(0, true);
        renderer.setSeriesShapesVisible(1, true);
        renderer.setSeriesShapesVisible(2, true);
        
        File XYChart = new File( "XYLineChart.png" ); 
        ChartUtilities.saveChartAsPNG( XYChart, chart, 600, 450);
        ChartFrame frame = new ChartFrame("My Chart", chart);
        frame.pack();
        frame.setVisible(true);
        
        
    }

}
