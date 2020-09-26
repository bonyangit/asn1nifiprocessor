package com.bonyansystem;

import java.io.*;
import java.util.Arrays;
import java.util.List;

import com.beanit.asn1bean.ber.types.BerEnum;

import org.apache.commons.io.FilenameUtils;

import pgw.*;

public class BonyanASN1Utility {

    public static void ASN1ToCsv(String inFilePath, String outDirectory, int BUFFER_SIZE) {
        // int fileIndex = 1;

        int totalRecordCount = 0;

        try (InputStream inputStream = new FileInputStream(new File(inFilePath));) {

            // #region
            byte[] firstBuffer = new byte[BUFFER_SIZE];
            ByteArrayOutputStream secondBuffer = new ByteArrayOutputStream();

            int TotalBytesInBuffer = 0;
            int readBytes = 0;
            int byte1 = -1;
            int byte2 = -1;
            int byte3 = -1;

            // BufferedWriter writer = new BufferedWriter(
            // new FileWriter(
            // outDirectory + "\\"
            // + FilenameUtils.getName(inFilePath).replace(
            // "." + FilenameUtils.getExtension(inFilePath), "_" + fileIndex + ".csv"),
            // false));
            // fileIndex++;

            String outputFileName = FilenameUtils.getName(inFilePath)
                    .replace("." + FilenameUtils.getExtension(inFilePath), ".csv");
            File ff = new File(outDirectory, outputFileName);

            BufferedWriter writer = new BufferedWriter(new FileWriter(ff, false));

            int recordCounter = 0;
            // int recordCounterForoutputFile = 0;

            String finalResult = "";
            boolean showInConsoleToo = false;
            // #endregion

            while ((readBytes = inputStream.read(firstBuffer)) != -1) {

                secondBuffer.write(Arrays.copyOfRange(firstBuffer, 0, readBytes));
                TotalBytesInBuffer = secondBuffer.size();

                int CurrRecordStartIndex = 0;

                while (!(CurrRecordStartIndex >= TotalBytesInBuffer)) {

                    // #region
                    byte1 = (int) secondBuffer.toByteArray()[CurrRecordStartIndex] & 0xff;
                    byte2 = (int) secondBuffer.toByteArray()[CurrRecordStartIndex + 1] & 0xff;
                    byte3 = (int) secondBuffer.toByteArray()[CurrRecordStartIndex + 2] & 0xff;

                    if (byte1 != 191 || byte2 != 79 || (byte3 != 129 && byte3 != 130)) {
                        throw new IOException("Record doesn't start with 0XBF4F or third byte is not 0x81 or 0x82");
                    }

                    int extraBytesToRead = 0;
                    int recordLen = 0;

                    if (byte3 == 129) {

                        int byte4 = ((int) secondBuffer.toByteArray()[CurrRecordStartIndex + 3] & 0xff);
                        recordLen = byte4 + 4;

                        if ((TotalBytesInBuffer - CurrRecordStartIndex) < recordLen) {
                            extraBytesToRead = (recordLen - (TotalBytesInBuffer - CurrRecordStartIndex));
                        }

                    } else {

                        recordLen = (secondBuffer.toByteArray()[CurrRecordStartIndex + 3]) << (Byte.SIZE * 1);
                        recordLen |= (secondBuffer.toByteArray()[CurrRecordStartIndex + 4] & 0xFF);
                        recordLen += 5;

                        if ((TotalBytesInBuffer - CurrRecordStartIndex) < recordLen) {
                            extraBytesToRead = (recordLen - (TotalBytesInBuffer - CurrRecordStartIndex));
                        }
                    }

                    ByteArrayOutputStream os = new ByteArrayOutputStream();
                    os.write(Arrays.copyOfRange(secondBuffer.toByteArray(), CurrRecordStartIndex,
                            CurrRecordStartIndex + recordLen - extraBytesToRead));

                    if (extraBytesToRead > 0) {

                        byte[] b = new byte[extraBytesToRead];
                        inputStream.read(b);
                        os.write(b);
                    }

                    InputStream is = new ByteArrayInputStream(os.toByteArray());
                    PGWRecord obj_decoded = new PGWRecord();
                    obj_decoded.decode(is);

                    // #endregion

                    // if (recordCounterForoutputFile >= 2000) {

                    // recordCounter = 0;
                    // finalResult = "";

                    // writer.close();

                    // writer = new BufferedWriter(new FileWriter(
                    // outDirectory + "\\"
                    // + FilenameUtils.getName(inFilePath).replace(
                    // "." + FilenameUtils.getExtension(inFilePath), "_" + fileIndex + ".csv"),
                    // false));
                    // fileIndex++;
                    // recordCounterForoutputFile = 0;
                    // }

                    if (recordCounter >= 200) {

                        if (showInConsoleToo)
                            System.out.println(finalResult);

                        writer.append(finalResult);
                        recordCounter = 0;
                        finalResult = "\r\n";
                    }

                    String result = "";

                    List<ServiceEvent> lstServiceEvent = null;
                    int recordExtensions_ServiceList_ServiceEvent_size = 0;

                    if (obj_decoded.getRecordExtensions() != null
                            && obj_decoded.getRecordExtensions().getServiceList() != null
                            && obj_decoded.getRecordExtensions().getServiceList().getServiceEvent() != null) {
                        lstServiceEvent = obj_decoded.getRecordExtensions().getServiceList().getServiceEvent();
                        recordExtensions_ServiceList_ServiceEvent_size = lstServiceEvent.size();
                    }

                    for (int subRecInd = 0; subRecInd <= recordExtensions_ServiceList_ServiceEvent_size; subRecInd++) {

                        if (!result.equals(""))
                            result += "\r\n";

                        // C : servedIMSI,
                        if (obj_decoded.getServedIMSI() != null)
                            result += BonyanUtility.TBCDStringToString(obj_decoded.getServedIMSI().toString());


                        result += ",";

                        // M: pGWAddress,
                        result += BonyanUtility.GSNAddressToString(obj_decoded.getPGWAddress()) + ",";

                        // O: dataVolumeGPRSUplink,dataVolumeGPRSDownlink,
                        if (obj_decoded.getListOfTrafficVolumes() != null) {
                            List<ChangeOfCharCondition> lstlistOfTrafficVolumes = obj_decoded.getListOfTrafficVolumes()
                                    .getChangeOfCharCondition();
                            int lstlstlistOfTrafficVolumes_Size = lstlistOfTrafficVolumes.size();

                            for (int i = 0; i < lstlstlistOfTrafficVolumes_Size; i++) {

                                if (lstlistOfTrafficVolumes.get(i).getDataVolumeGPRSUplink() != null)
                                    result += lstlistOfTrafficVolumes.get(i).getDataVolumeGPRSUplink();

                                if ((i + 1) < lstlstlistOfTrafficVolumes_Size)
                                    result += "-";
                            }

                            result += ",";

                            for (int i = 0; i < lstlstlistOfTrafficVolumes_Size; i++) {

                                if (lstlistOfTrafficVolumes.get(i).getDataVolumeGPRSDownlink() != null)
                                    result += lstlistOfTrafficVolumes.get(i).getDataVolumeGPRSDownlink();

                                if ((i + 1) < lstlstlistOfTrafficVolumes_Size)
                                    result += "-";
                            }

                            result += ",";

                        } else
                            result += ",,";

                        // M: recordOpeningTime,
                        result += BonyanUtility.octetDateTimeToString(obj_decoded.getRecordOpeningTime().toString())
                                + ",";

                        // M: duration,
                        result += obj_decoded.getDuration() + ",";

                        // M: causeForRecClosing,
                        result += obj_decoded.getCauseForRecClosing() + ",";

                        // O: nodeID,
                        if (obj_decoded.getNodeID() != null)
                            result += obj_decoded.getNodeID();

                        result += ",";

                        // O: url,serviceCode,
                        if (recordExtensions_ServiceList_ServiceEvent_size > 0) {

                            if (lstServiceEvent.get(subRecInd).getUrl() != null)
                                result += lstServiceEvent.get(subRecInd).getUrl();

                            result += ",";

                            if (lstServiceEvent.get(subRecInd).getServiceCode() != null)
                                result += lstServiceEvent.get(subRecInd).getServiceCode();

                            result += ",";

                        } else
                            result += ",,";

                        // O: localSequenceNumber,
                        if (obj_decoded.getLocalSequenceNumber() != null)
                            result += obj_decoded.getLocalSequenceNumber();

                        result += ",";

                        // O: servedMSISDN,
                        if (obj_decoded.getServedMSISDN() != null)
                            result += BonyanUtility.TBCDStringToString(obj_decoded.getServedMSISDN().toString());

                        result += ",";

                        // O: servedIMEISV,
                        if (obj_decoded.getServedIMEISV() != null)
                            result += BonyanUtility.TBCDStringToString(obj_decoded.getServedIMEISV().toString());

                        result += ",";

                        // O: downlinkVolume,uplinkVolume,
                        if (recordExtensions_ServiceList_ServiceEvent_size > 0) {

                            if (lstServiceEvent.get(subRecInd).getDownlinkVolume() != null)
                                result += lstServiceEvent.get(subRecInd).getDownlinkVolume();

                            result += ",";

                            if (lstServiceEvent.get(subRecInd).getUplinkVolume() != null)
                                result += lstServiceEvent.get(subRecInd).getUplinkVolume();

                            result += ",";
                        } else
                            result += ",,";

                        // O: chargingRuleBaseName,ratingGroup
                        if (obj_decoded.getListOfServiceData() != null) {

                            List<ChangeOfServiceConditions> lstgetListOfServiceData = obj_decoded.getListOfServiceData()
                                    .getChangeOfServiceConditions();

                            int lstgetListOfServiceData_Size = lstgetListOfServiceData.size();

                            for (int i = 0; i < lstgetListOfServiceData_Size; i++) {
                                result += lstgetListOfServiceData.get(i).getChargingRuleBaseName();

                                if ((i + 1) < lstgetListOfServiceData_Size)
                                    result += "-";
                            }

                            result += ",";

                            for (int i = 0; i < lstgetListOfServiceData_Size; i++) {
                                result += lstgetListOfServiceData.get(i).getRatingGroup();

                                if ((i + 1) < lstgetListOfServiceData_Size)
                                    result += "-";
                            }

                        } else
                            result += ",";

                        // ==================================================================================
                        // Mikhaham hata agar hichi ServiceEvent nadasht , dakhel for beshavad , baraye
                        // hamin bala <= gozashtam va inja aan ra control kardam ke break konad
                        if (subRecInd == recordExtensions_ServiceList_ServiceEvent_size - 1)
                            break;
                    }

                    if (!finalResult.equals("") && !finalResult.equals("\r\n"))
                        finalResult += "\r\n";

                    finalResult += result;

                    recordCounter++;
                    totalRecordCount++;
                    // recordCounterForoutputFile++;

                    CurrRecordStartIndex += (recordLen - extraBytesToRead);

                    // check if there is enough bytes to read
                    if (TotalBytesInBuffer - CurrRecordStartIndex < 5) {

                        secondBuffer.reset();

                        if (TotalBytesInBuffer - CurrRecordStartIndex > 0)
                            secondBuffer
                                    .write(Arrays.copyOfRange(firstBuffer, readBytes-(TotalBytesInBuffer - CurrRecordStartIndex), readBytes));

                        // if (TotalBytesInBuffer - CurrRecordStartIndex > 0)
                        //     secondBuffer
                        //             .write(Arrays.copyOfRange(firstBuffer, CurrRecordStartIndex, TotalBytesInBuffer));

                        // System.out.println("LESS THAN FIVE BYTES : " +
                        // byteArrayToHex(secondBuffer.toByteArray()));

                        break;
                    }

                }

            }

            if (showInConsoleToo)
                System.out.println(finalResult);

            if(!finalResult.equals("") && !finalResult.equals("\r\n"))
                writer.append(finalResult);

            writer.close();
            System.out.println(totalRecordCount);

        } catch (

                IOException ex) {
            ex.printStackTrace();
        }
    }

    public static void ASN1ToJson(String inFilePath, String outDirectory, int BUFFER_SIZE) {
        // String DirectoryPath ="C:\\Users\\Neda\\Desktop\\cpm\\temp2\\";
        // String fileName = "G_GECRHA01_ERHpgwcdr20200909105436000008584_07642477.dat";

        int fileIndex = 1;

        try (InputStream inputStream = new FileInputStream(new File(inFilePath));) {

            byte[] firstBuffer = new byte[BUFFER_SIZE];
            ByteArrayOutputStream secondBuffer = new ByteArrayOutputStream();

            int TotalBytesInBuffer = 0;
            int readBytes = 0;
            int byte1 = -1;
            int byte2 = -1;
            int byte3 = -1;



            String outputFileName = FilenameUtils.getName(inFilePath).replace(
                    "." + FilenameUtils.getExtension(inFilePath), "_" + fileIndex + ".json");

            File ff = new File(outDirectory, outputFileName);

            BufferedWriter writer = new BufferedWriter(new FileWriter(ff, false));


//            BufferedWriter writer = new BufferedWriter(
//                    new FileWriter(
//                            outDirectory + "\\"
//                                    + FilenameUtils.getName(inFilePath).replace(
//                                    "." + FilenameUtils.getExtension(inFilePath), "_" + fileIndex + ".json"),
//                            false));
            fileIndex++;
            writer.append("[");

            int recordCounter = 0;
            int recordCounterForoutputFile = 0;

            String finalResult = "";
            // boolean firstRecAdded = false;
            boolean showInConsoleToo = false;

            while ((readBytes = inputStream.read(firstBuffer)) != -1) {

                secondBuffer.write(Arrays.copyOfRange(firstBuffer, 0, readBytes));
                TotalBytesInBuffer = secondBuffer.size();

                // System.out.println("=============first while===============");
                // System.out.println("TotalBytesInBuffer : " + TotalBytesInBuffer);
                // System.out.println("Buffer1 : " + byteArrayToHex(firstBuffer));
                // System.out.println("Buffer2 : " +
                // byteArrayToHex(secondBuffer.toByteArray()));

                int CurrRecordStartIndex = 0;

                while (!(CurrRecordStartIndex >= TotalBytesInBuffer)) {
                    // System.out.println("=============second while===============");

                    byte1 = (int) secondBuffer.toByteArray()[CurrRecordStartIndex] & 0xff;
                    byte2 = (int) secondBuffer.toByteArray()[CurrRecordStartIndex + 1] & 0xff;
                    byte3 = (int) secondBuffer.toByteArray()[CurrRecordStartIndex + 2] & 0xff;

                    if (byte1 != 191 || byte2 != 79 || (byte3 != 129 && byte3 != 130)) {
                        throw new IOException("Record doesn't start with 0XBF4F or third byte is not 0x81 or 0x82");
                    }

                    int extraBytesToRead = 0;
                    int recordLen = 0;

                    if (byte3 == 129) {
                        // System.out.println("byte3 : 81");

                        int byte4 = ((int) secondBuffer.toByteArray()[CurrRecordStartIndex + 3] & 0xff);
                        recordLen = byte4 + 4;

                        if ((TotalBytesInBuffer - CurrRecordStartIndex) < recordLen) {
                            extraBytesToRead = (recordLen - (TotalBytesInBuffer - CurrRecordStartIndex));
                        }

                        // System.out.println("recordLen : " + recordLen + " extraBytesToRead : " +
                        // extraBytesToRead + " CurrRecordStartIndex : " + CurrRecordStartIndex);

                    } else {

                        // System.out.println("byte3 : 82");

                        recordLen = (secondBuffer.toByteArray()[CurrRecordStartIndex + 3]) << (Byte.SIZE * 1);
                        recordLen |= (secondBuffer.toByteArray()[CurrRecordStartIndex + 4] & 0xFF);
                        recordLen += 5;

                        if ((TotalBytesInBuffer - CurrRecordStartIndex) < recordLen) {
                            extraBytesToRead = (recordLen - (TotalBytesInBuffer - CurrRecordStartIndex));
                        }

                        // System.out.println("recordLen : " + recordLen + " extraBytesToRead : " +
                        // extraBytesToRead + " CurrRecordStartIndex : " + CurrRecordStartIndex);

                    }

                    ByteArrayOutputStream os = new ByteArrayOutputStream();
                    os.write(Arrays.copyOfRange(secondBuffer.toByteArray(), CurrRecordStartIndex,
                            CurrRecordStartIndex + recordLen - extraBytesToRead));

                    if (extraBytesToRead > 0) {

                        byte[] b = new byte[extraBytesToRead];
                        inputStream.read(b);
                        os.write(b);
                    }

                    // System.out.println("CurrRec : " + byteArrayToHex(os.toByteArray()));

                    InputStream is = new ByteArrayInputStream(os.toByteArray());
                    PGWRecord obj_decoded = new PGWRecord();
                    obj_decoded.decode(is);

                    if (recordCounterForoutputFile >= 2000) {
                        writer.append(BonyanUtility.removeEnd(finalResult, ","));
                        writer.append("]");
                        recordCounter = 0;
                        finalResult = "";

                        writer.close();


                        outputFileName = FilenameUtils.getName(inFilePath).replace(
                                "." + FilenameUtils.getExtension(inFilePath), "_" + fileIndex + ".json");

                        ff = new File(outDirectory, outputFileName);

                        writer = new BufferedWriter(new FileWriter(ff, false));



//                        writer = new BufferedWriter(new FileWriter(
//                                outDirectory + "\\" + FilenameUtils.getName(inFilePath).replace(
//                                        "." + FilenameUtils.getExtension(inFilePath), "_" + fileIndex + ".json"),
//                                false));



                        writer.append("[");
                        fileIndex++;
                        recordCounterForoutputFile = 0;
                    }

                    if (recordCounter >= 200) {

                        if (showInConsoleToo)
                            System.out.println(finalResult);

                        writer.append(finalResult);
                        recordCounter = 0;
                        finalResult = "";
                    }

                    finalResult += "{\r\n\t";

                    String result = "";
                    result += "\"recordType\":" + obj_decoded.getRecordType() + ",";

                    result += "\r\n\t";

                    if (obj_decoded.getServedIMSI() != null)
                        result += "\"servedIMSI\":"
                                + BonyanUtility.TBCDStringToString(obj_decoded.getServedIMSI().toString()) + ",";
                    else
                        result += "\"servedIMSI\":,";

                    result += "\r\n\t";

                    result += "\"pGWAddress\":" + BonyanUtility.GSNAddressToStringJson(obj_decoded.getPGWAddress())
                            + ",";

                    result += "\r\n\t";

                    result += "\"chargingID\":" + obj_decoded.getChargingID() + ",";

                    result += "\r\n\t";
                    result += "\"servingNodeAddress\":[";

                    List<GSNAddress> lstServingNodeAddress = obj_decoded.getServingNodeAddress().getGSNAddress();
                    int lstServingNodeAddress_Size = lstServingNodeAddress.size();

                    // String ExtraTag = "";
                    // if (lstServingNodeAddress_Size > 0) {
                    //
                    // ExtraTag += "\r\n\t";
                    // ExtraTag += "\"NEDA_TAG_servingNodeAddress\":1,";
                    // }

                    for (int i = 0; i < lstServingNodeAddress_Size; i++) {
                        result += BonyanUtility.GSNAddressToStringJson(lstServingNodeAddress.get(i));

                        if ((i + 1) < lstServingNodeAddress_Size)
                            result += ",";
                    }

                    result += "],";

                    // if (ExtraTag != "")
                    // result += ExtraTag;

                    result += "\r\n\t";

                    result += "\"accessPointNameNI\":\"" + obj_decoded.getAccessPointNameNI() + "\",";

                    result += "\r\n\t";

                    result += "\"pdpPDNType\":\"" + obj_decoded.getPdpPDNType() + "\",";

                    result += "\r\n\t";

                    if (obj_decoded.getServedPDPPDNAddress() != null)
                        result += "\"servedPDPPDNAddress\":"
                                + BonyanUtility.PDPAddressToString(obj_decoded.getServedPDPPDNAddress()) + ",";
                    else
                        result += "\"servedPDPPDNAddress\":{},";

                    result += "\r\n\t";
                    result += "\"dynamicAddressFlag\":" + obj_decoded.getDynamicAddressFlag() + ",";

                    result += "\r\n\t";

                    result += "\"listOfTrafficVolumes\":[";
                    if (obj_decoded.getListOfTrafficVolumes() != null) {
                        List<ChangeOfCharCondition> lstlistOfTrafficVolumes = obj_decoded.getListOfTrafficVolumes()
                                .getChangeOfCharCondition();
                        int lstlstlistOfTrafficVolumes_Size = lstlistOfTrafficVolumes.size();

                        // if (lstlstlistOfTrafficVolumes_Size == 0) {
                        //
                        // ExtraTag += "\r\n\t";
                        // ExtraTag += "\"NEDA_TAG_listOfTrafficVolumes\":1,";
                        //
                        // }

                        for (int i = 0; i < lstlstlistOfTrafficVolumes_Size; i++) {
                            result += BonyanUtility.ChangeOfCharConditionToString(lstlistOfTrafficVolumes.get(i));

                            if ((i + 1) < lstlstlistOfTrafficVolumes_Size)
                                result += ",";
                        }
                    }
                    result += "],";

                    // if(ExtraTag != "")
                    // result += ExtraTag;
                    //
                    // ExtraTag = "";

                    result += "\r\n\t";
                    result += "\"recordOpeningTime\":\""
                            + BonyanUtility.octetDateTimeToString(obj_decoded.getRecordOpeningTime().toString())
                            + "\",";

                    result += "\r\n\t";
                    result += "\"duration\":" + obj_decoded.getDuration() + ",";

                    result += "\r\n\t";
                    result += "\"causeForRecClosing\":" + obj_decoded.getCauseForRecClosing() + ",";

                    result += "\r\n\t";

                    if (obj_decoded.getDiagnostics() != null)
                        result += "\"diagnostics\":" + BonyanUtility.DiagnosticsToString(obj_decoded.getDiagnostics())
                                + ",";
                    else
                        result += "\"diagnostics\":null,";

                    result += "\r\n\t";
                    result += "\"recordSequenceNumber\":" + obj_decoded.getRecordSequenceNumber() + ",";

                    if (obj_decoded.getNodeID() != null)
                        result += "\"nodeID\":\"" + obj_decoded.getNodeID() + "\",";
                    else
                        result += "\"nodeID\":null,";

                    result += "\r\n\t";
                    if (obj_decoded.getRecordExtensions() != null)
                        result += "\"recordExtensions\":"
                                + BonyanUtility.ContentInfoToStringJson(obj_decoded.getRecordExtensions()) + ",";
                    else
                        result += "\"recordExtensions\":null,";

                    result += "\r\n\t";
                    result += "\"localSequenceNumber\":" + obj_decoded.getLocalSequenceNumber() + ",";

                    result += "\r\n\t";
                    result += "\"apnSelectionMode\":" + obj_decoded.getApnSelectionMode() + ",";

                    result += "\r\n\t";

                    if (obj_decoded.getServedMSISDN() != null)
                        result += "\"servedMSISDN\":\""
                                + BonyanUtility.TBCDStringToString(obj_decoded.getServedMSISDN().toString()) + "\",";
                    else
                        result += "\"servedMSISDN\":null,";

                    result += "\r\n\t";
                    result += "\"chargingCharacteristics\":\"" + obj_decoded.getChargingCharacteristics() + "\",";

                    result += "\r\n\t";
                    result += "\"chChSelectionMode\":" + obj_decoded.getChChSelectionMode() + ",";

                    // ???????????????????
                    if (obj_decoded.getIMSsignalingContext() != null) {
                        result += "\r\n\t";
                        result += "\"iMSsignalingContext?????\":\"" + obj_decoded.getIMSsignalingContext() + "\",";
                    }

                    result += "\r\n\t";
                    if (obj_decoded.getExternalChargingID() != null)
                        result += "\"externalChargingID\":\"" + obj_decoded.getExternalChargingID() + "\",";
                    else
                        result += "\"externalChargingID\":null,";

                    result += "\r\n\t";
                    if (obj_decoded.getServingNodePLMNIdentifier() != null)
                        result += "\"servingNodePLMNIdentifier\":{" + " \"MCC\":"
                                + BonyanUtility.TBCDStringToString(
                                obj_decoded.getServingNodePLMNIdentifier().toString().substring(0, 4))
                                + ",\"MNC\":" + BonyanUtility.TBCDStringToString(
                                obj_decoded.getServingNodePLMNIdentifier().toString().substring(4, 6))
                                + "},";
                    else
                        result += "\"servingNodePLMNIdentifier\":null,";

                    result += "\r\n\t";
                    if (obj_decoded.getPSFurnishChargingInformation() != null)
                        result += "\"pSFurnishChargingInformation\":" + BonyanUtility
                                .PSFurnishChargingInformationtoString(obj_decoded.getPSFurnishChargingInformation())
                                + ",";
                    else
                        result += "\"pSFurnishChargingInformation\":null,";

                    result += "\r\n\t";
                    if (obj_decoded.getServedIMEISV() != null)
                        result += "\"servedIMEISV?????\":\""
                                + BonyanUtility.TBCDStringToString(obj_decoded.getServedIMEISV().toString()) + "\",";
                    else
                        result += "\"servedIMEISV?????\":null,";

                    result += "\r\n\t";
                    result += "\"rATType\":" + obj_decoded.getRATType() + ",";

                    result += "\r\n\t";
                    result += "\"mSTimeZone?????\":\"" + obj_decoded.getMSTimeZone() + "\",";

                    result += "\r\n\t";
                    result += "\"userLocationInformation?????\":\"" + obj_decoded.getUserLocationInformation() + "\",";

                    result += "\r\n\t";
                    result += "\"cAMELChargingInformation?????\":\"" + obj_decoded.getCAMELChargingInformation()
                            + "\",";

                    // listOfServiceData
                    result += "\r\n\t";
                    result += "\"listOfServiceData\":[";
                    if (obj_decoded.getListOfServiceData() != null) {
                        List<ChangeOfServiceConditions> lstgetListOfServiceData = obj_decoded.getListOfServiceData()
                                .getChangeOfServiceConditions();
                        int lstgetListOfServiceData_Size = lstgetListOfServiceData.size();

                        // if (lstgetListOfServiceData_Size == 0)
                        // {
                        // ExtraTag += "\r\n\t";
                        // ExtraTag += "\"NEDA_TAG_listOfServiceData\":1,";
                        //
                        // }

                        for (int i = 0; i < lstgetListOfServiceData_Size; i++) {
                            result += BonyanUtility.ChangeOfServiceConditionsToString(lstgetListOfServiceData.get(i));

                            if ((i + 1) < lstgetListOfServiceData_Size)
                                result += ",";
                        }
                    }
                    result += "],";

                    // if(ExtraTag != "")
                    // result += ExtraTag;
                    //
                    // ExtraTag = "";

                    result += "\r\n\t";
                    result += "\"servingNodeType\":[";

                    if (obj_decoded.getServingNodeType() != null) {
                        List<BerEnum> lstServingNodeType = obj_decoded.getServingNodeType().getBerEnum();
                        int lstServingNodeType_size = lstServingNodeType.size();

                        // if (lstServingNodeType_size == 0)
                        // {
                        // ExtraTag += "\r\n\t";
                        // ExtraTag += "\"NEDA_TAG_servingNodeType\":1,";
                        // }

                        for (int i = 0; i < lstServingNodeType_size; i++) {
                            result += lstServingNodeType.get(i);

                            if ((i + 1) < lstServingNodeType_size)
                                result += ",";
                        }
                    }
                    result += "],";

                    // if(ExtraTag != "")
                    // result += ExtraTag;
                    // ExtraTag = "";

                    result += "\r\n\t";
                    if (obj_decoded.getServedMNNAI() != null)
                        result += "\"servedMNNAI\":"
                                + BonyanUtility.SubscriptionIDToString(obj_decoded.getServedMNNAI()) + ",";
                    else
                        result += "\"servedMNNAI\":null,";

                    //
                    result += "\r\n\t";
                    if (obj_decoded.getPGWPLMNIdentifier() != null)
                        result += "\"pGWPLMNIdentifier\":{" + " \"MCC\":"
                                + BonyanUtility.TBCDStringToString(
                                obj_decoded.getPGWPLMNIdentifier().toString().substring(0, 4))
                                + ",\"MNC\":" + BonyanUtility.TBCDStringToString(
                                obj_decoded.getPGWPLMNIdentifier().toString().substring(4, 6))
                                + "},";
                    else
                        result += "\"pGWPLMNIdentifier\":null,";

                    result += "\r\n\t";
                    if (obj_decoded.getStartTime() != null)
                        result += "\"startTime\":\""
                                + BonyanUtility.octetDateTimeToString(obj_decoded.getStartTime().toString()) + "\",";
                    else
                        result += "\"startTime\":null,";

                    result += "\r\n\t";
                    if (obj_decoded.getStopTime() != null)
                        result += "\"stopTime\":\""
                                + BonyanUtility.octetDateTimeToString(obj_decoded.getStopTime().toString()) + "\",";
                    else
                        result += "\"stopTime\":null,";

                    result += "\r\n\t";
                    if (obj_decoded.getServed3gpp2MEID() != null)
                        result += "\"served3gpp2MEID??????????\":\"" + obj_decoded.getServed3gpp2MEID() + "\",";
                    else
                        result += "\"served3gpp2MEID??????????\":null,";

                    result += "\r\n\t";
                    result += "\"pDNConnectionChargingID\":" + obj_decoded.getPDNConnectionChargingID() + ",";

                    // ???????????????????
                    if (obj_decoded.getIMSIunauthenticatedFlag() != null) {
                        result += "\r\n\t";
                        result += "\"iMSIunauthenticatedFlag?????\":\"" + obj_decoded.getIMSIunauthenticatedFlag()
                                + "\",";

                    }

                    result += "\r\n\t";
                    if (obj_decoded.getUserCSGInformation() != null)
                        result += "\"UserCSGInformationToString\":"
                                + BonyanUtility.UserCSGInformationToString(obj_decoded.getUserCSGInformation()) + ",";
                    else
                        result += "\"UserCSGInformationToString\":null,";
                    //

                    result += "\r\n\t";
                    if (obj_decoded.getThreeGPP2UserLocationInformation() != null)
                        result += "\"threeGPP2UserLocationInformation????????\":"
                                + obj_decoded.getThreeGPP2UserLocationInformation() + ",";
                    else
                        result += "\"threeGPP2UserLocationInformation????????\":null,";

                    result += "\r\n\t";
                    if (obj_decoded.getServedPDPPDNAddressExt() != null)
                        result += "\"servedPDPPDNAddressExt\":"
                                + BonyanUtility.PDPAddressToString(obj_decoded.getServedPDPPDNAddressExt()) + ",";
                    else
                        result += "\"servedPDPPDNAddressExt\":null,";

                    // ???????????????????
                    if (obj_decoded.getLowPriorityIndicator() != null) {
                        result += "\r\n\t";
                        result += "\"lowPriorityIndicator?????\":\"" + obj_decoded.getLowPriorityIndicator() + "\",";

                    }

                    result += "\r\n\t";
                    result += "\"dynamicAddressFlagExt\":" + obj_decoded.getDynamicAddressFlagExt() + ",";

                    //
                    if (obj_decoded.getPGWiPv6AddressUsed() != null)
                        result += "\"pGWiPv6AddressUsed\":"
                                + BonyanUtility.GSNAddressToStringJson(obj_decoded.getPGWiPv6AddressUsed()) + ",";
                    else
                        result += "\"pGWiPv6AddressUsed\":null,";

                    result += "\r\n\t";
                    result += "\"sGiPtPTunnellingMethod\":" + obj_decoded.getSGiPtPTunnellingMethod() + ",";

                    result += "\r\n\t";
                    result += "\"uNIPDUCPOnlyFlag\":" + obj_decoded.getUNIPDUCPOnlyFlag() + ",";

                    result += "\r\n\t";
                    if (obj_decoded.getServingPLMNRateControl() != null)
                        result += "\"servingPLMNRateControl\":"
                                + BonyanUtility.ServingPLMNRateControlToString(obj_decoded.getServingPLMNRateControl())
                                + ",";
                    else
                        result += "\"servingPLMNRateControl\":null,";

                    result += "\r\n\t";
                    if (obj_decoded.getAPNRateControl() != null)
                        result += "\"aPNRateControl\":"
                                + BonyanUtility.APNRateControlToString(obj_decoded.getAPNRateControl()) + ",";
                    else
                        result += "\"aPNRateControl\":null,";

                    result += "\r\n\t";
                    result += "\"pDPPDNTypeExtension\":" + obj_decoded.getPDPPDNTypeExtension() + ",";

                    result += "\r\n\t";
                    if (obj_decoded.getMOExceptionDataCounter() != null) {
                        result += "\"MOExceptionDataCounterToString\":"
                                + BonyanUtility.MOExceptionDataCounterToString(obj_decoded.getMOExceptionDataCounter())
                                + ",";
                    } else
                        result += "\"MOExceptionDataCounterToString\":null,";

                    result = result.substring(0, result.length() - 1);

                    // result += "\r\n\t";
                    // result += "\" \":";

                    finalResult += result + "\n},";

                    recordCounter++;
                    recordCounterForoutputFile++;

                    CurrRecordStartIndex += (recordLen - extraBytesToRead);
                    // System.out.println("NEXT INDEX : " + CurrRecordStartIndex);

                    // check if there is enough bytes to read
                    if (TotalBytesInBuffer - CurrRecordStartIndex < 5) {

                        secondBuffer.reset();

                        if (TotalBytesInBuffer - CurrRecordStartIndex > 0)
                            secondBuffer
                                    .write(Arrays.copyOfRange(firstBuffer, readBytes-(TotalBytesInBuffer - CurrRecordStartIndex), readBytes));

                        // if (TotalBytesInBuffer - CurrRecordStartIndex > 0)
                        //     secondBuffer
                        //             .write(Arrays.copyOfRange(firstBuffer, CurrRecordStartIndex, TotalBytesInBuffer));

                        // System.out.println("LESS THAN FIVE BYTES : " +
                        // byteArrayToHex(secondBuffer.toByteArray()));

                        break;
                    }

                }

            }

            if (showInConsoleToo)
                System.out.println(finalResult);

            writer.append(BonyanUtility.removeEnd(finalResult, ","));
            writer.append("]");
            writer.close();
            System.out.println("finish");

        } catch (IOException ex) {
            ex.printStackTrace();
        }

        // try {

        // DataInputStream dis = new DataInputStream(
        // new BufferedInputStream(
        // new FileInputStream(new
        // File("C:\\Users\\Neda\\Desktop\\cpm\\temp\\file02.dat"))));

        // byte[] encodedBytes = dis.readAllBytes();
        // InputStream is = new ByteArrayInputStream(encodedBytes);

        // PGWCDR obj_decoded = new PGWCDR();
        // obj_decoded.decode(is);

        // System.out.println(obj_decoded);

        // } catch (IOException ex) {
        // ex.printStackTrace();
        // }

    }

}
