package com.bonyansystem;

import java.io.File;

import org.ietf.jgss.Oid;


public final class App {
    private App() {
    }



    private static final int BUFFER_SIZE = 4096; // 4KB

    public static void main(String[] args) {

        if (args.length < 5 || !(args[0].equals("-json") || args[0].equals("-csv"))
                || !(args[1].equals("-ifile") || args[1].equals("-odir"))
                || !(args[3].equals("-ifile") || args[3].equals("-odir")) || args[1].equals(args[3])) {
            System.out.println(
                    "use this program like : \n java -jar bonyanASN1.jar -csv|-json -ifile inputFilePath -odir outputdirectory");
            return;
        }

        String inFile = "";
        String outDir = "";

        if (args[1].equals("-ifile")) {
            inFile = args[2];
            outDir = args[4];
        } else {
            inFile = args[4];
            outDir = args[2];
        }

        File f = new File(inFile);
        if (!f.exists()) {
            System.out.println("input file does not exist : " + inFile);
            return;
        }

        File dir = new File(outDir);
        if (!dir.exists()) {
            System.out.println("directory does not exist : " + outDir);
            return;
        }

        if (args[0].equals("-json"))
            BonyanASN1Utility.ASN1ToJson(inFile, outDir, BUFFER_SIZE);
        else
            BonyanASN1Utility.ASN1ToCsv(inFile, outDir, BUFFER_SIZE);

    }
}
