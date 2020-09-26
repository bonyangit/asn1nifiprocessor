package com.bonyansystem;

import java.io.*;
import java.util.Arrays;
import java.util.List;

import com.beanit.asn1bean.ber.types.BerInteger;
import com.beanit.asn1bean.ber.types.BerOctetString;

import org.apache.commons.io.FilenameUtils;

import pgw.*;

import com.beanit.asn1bean.ber.types.BerEnum;

public class BonyanUtility {
    public static String removeEnd(String str, String remove) {
        if (str == "" || remove == "") {
            return str;
        }
        if (str.endsWith(remove)) {
            return str.substring(0, str.length() - remove.length());
        }
        return str;
    }

    public static String byteArrayToHex(byte[] a) {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for (byte b : a)
            sb.append(String.format("%02x", b));
        return sb.toString();
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public static String TBCDStringToString(String s) throws IOException {

        if (s.length() % 2 != 0)
            throw new IOException("input string is not in correct format");

        char[] charArray = s.toCharArray();

        String result = "";
        for (int i = 0; i < charArray.length; i += 2) {
            result += String.valueOf(charArray[i + 1]) + String.valueOf(charArray[i]);
        }

        charArray = result.toCharArray();
        boolean firstNonDigitReached = false;
        result = "";

        for (int i = 0; i < charArray.length; i++) {

            if (!Character.isDigit(charArray[i]) && !firstNonDigitReached) {
                firstNonDigitReached = true;
            }

            if (firstNonDigitReached) {
                if (charArray[i] != 'F' && charArray[i] != 'f') {
                    throw new IOException("input string is not in correct format");
                }
            } else
                result += String.valueOf(charArray[i]);

        }

        return result;
    }

    public static int byteToUnsignedByte(byte b) {
        return (int) b & 0xff;
    }

    public static String GSNAddressToString(IPAddress address) throws IOException {

        // servedPDPPDNAddress = 01A1:20B3:0:0:0:0:0:0
        // 01A1 20B3 0000 0000 0000 0000 0000 0000

        String result = "";

        IPBinaryAddress ipBinary = address.getIPBinaryAddress();
        if (ipBinary != null) {
            if (ipBinary.getIPBinV4Address() != null) {
                byte[] tmp = hexStringToByteArray(ipBinary.getIPBinV4Address().toString());
                result += byteToUnsignedByte(tmp[0]) + "." + byteToUnsignedByte(tmp[1]) + "."
                        + byteToUnsignedByte(tmp[2]) + "." + byteToUnsignedByte(tmp[3]);
            }

            if (ipBinary.getIPBinV6Address() != null) {
                String ipV6 = ipBinary.getIPBinV6Address().toString();
                result += ipV6.substring(0, 4) + ":" + ipV6.substring(4, 8) + ":" + ipV6.substring(8, 12) + ":"
                        + ipV6.substring(12, 16) + ":" + ipV6.substring(16, 20) + ":" + ipV6.substring(20, 24) + ":"
                        + ipV6.substring(24, 28) + ":" + ipV6.substring(28, 32);
            }
        } else {
            IPTextRepresentedAddress ipText = address.getIPTextRepresentedAddress();

            if (ipText.getIPTextV4Address() != null)
                result += ipText.getIPTextV4Address().toString();
            else
                result += ipText.getIPTextV6Address().toString();
        }

        return result;
    }

    public static String GSNAddressToStringJson(IPAddress address) throws IOException {

        String result = "{";

        IPBinaryAddress ipBinary = address.getIPBinaryAddress();
        if (ipBinary != null) {
            if (ipBinary.getIPBinV4Address() != null) {
                byte[] tmp = hexStringToByteArray(ipBinary.getIPBinV4Address().toString());
                result += "\"IPBinV4Address\":\"" + byteToUnsignedByte(tmp[0]) + "." + byteToUnsignedByte(tmp[1]) + "."
                        + byteToUnsignedByte(tmp[2]) + "." + byteToUnsignedByte(tmp[3]) + "\"";
            }

            if (ipBinary.getIPBinV6Address() != null){

                String ipV6 = ipBinary.getIPBinV6Address().toString();
                result += "\"IPBinV6Address\":\"" + ipV6.substring(0, 4) + ":" + ipV6.substring(4, 8) + ":" + ipV6.substring(8, 12) + ":"
                        + ipV6.substring(12, 16) + ":" + ipV6.substring(16, 20) + ":" + ipV6.substring(20, 24) + ":"
                        + ipV6.substring(24, 28) + ":" + ipV6.substring(28, 32)+ "\"";
            }
        } else {
            IPTextRepresentedAddress ipText = address.getIPTextRepresentedAddress();

            if (ipText.getIPTextV4Address() != null)
                result += "\"IPTextV4Address\":\"" + ipText.getIPTextV4Address().toString() + "\"";
            else
                result += "\"IPTextV6Address\":\"" + ipText.getIPTextV6Address().toString() + "\"";
        }

        result += "}";
        return result;
    }

    public static String PDPAddressToString(PDPAddress address) throws IOException {

        String result = "{";

        IPAddress ipAddress = address.getIPAddress();
        if (ipAddress != null)
            result += "\"ipAddress\":" + GSNAddressToStringJson(ipAddress);
        else
            result += "\"ETSIAddress\":\"" + address.getETSIAddress() + "\"";

        result += "}";

        return result;
    }

    public static String octetDateTimeToString(String dt) throws IOException {

        String result = "";

        if (dt.length() != 18)
            throw new IOException("input string is not in correct format");

        result += dt.substring(0, 2) + "-" + dt.substring(2, 4) + "-" + dt.substring(4, 6) + " " + dt.substring(6, 8)
                + ":" + dt.substring(8, 10) + ":" + dt.substring(10, 12)
                + (char) Integer.parseInt(dt.substring(12, 14), 16) + dt.substring(14, 16) + ":" + dt.substring(16, 18);

        return result;
    }

    public static String EPCQoSInformationToString(EPCQoSInformation obj) {
        String result = "\t{";
        result += "\t\"QCI\":" + obj.getQCI();

        result += ",\r\n\t\"maxRequestedBandwithUL\":";
        if (obj.getMaxRequestedBandwithUL() != null)
            result += obj.getMaxRequestedBandwithUL();
        else
            result += "null";

        result += ",\r\n\t\"maxRequestedBandwithDL\":";
        if (obj.getMaxRequestedBandwithDL() != null)
            result += obj.getMaxRequestedBandwithDL();
        else
            result += "null";

        result += ",\r\n\t\"guaranteedBitrateUL\":";
        if (obj.getGuaranteedBitrateUL() != null)
            result += obj.getGuaranteedBitrateUL();
        else
            result += "null";

        result += ",\r\n\t\"guaranteedBitrateDL\":";
        if (obj.getGuaranteedBitrateDL() != null)
            result += obj.getGuaranteedBitrateDL();
        else
            result += "null";

        result += ",\r\n\t\"aRP\":";
        if (obj.getARP() != null)
            result += obj.getARP();
        else
            result += "null";

        result += ",\r\n\t\"aPNAggregateMaxBitrateUL\":";
        if (obj.getAPNAggregateMaxBitrateUL() != null)
            result += obj.getAPNAggregateMaxBitrateUL();
        else
            result += "null";

        result += ",\r\n\t\"aPNAggregateMaxBitrateDL\":";
        if (obj.getAPNAggregateMaxBitrateDL() != null)
            result += obj.getAPNAggregateMaxBitrateDL();
        else
            result += "null";

        result += "\t}";
        return result;
    }

    public static String ChangeOfCharConditionToString(ChangeOfCharCondition obj) throws IOException {
        String result = "\t{";

        result += "\r\n\t\"qosRequested\":";
        if (obj.getQosRequested() != null)
            result += "\"" + obj.getQosRequested() + "\"";
        else
            result += "null";

        result += ",\r\n\t";
        result += "\"qosNegotiated\":";
        if (obj.getQosNegotiated() != null)
            result += "\"" + obj.getQosNegotiated() + "\"";
        else
            result += "null";

        result += ",\r\n\t";
        result += "\"dataVolumeGPRSUplink\":";
        if (obj.getDataVolumeGPRSUplink() != null)
            result += obj.getDataVolumeGPRSUplink();
        else
            result += "null";

        result += ",\r\n\t";
        result += "\"dataVolumeGPRSDownlink\":";
        if (obj.getDataVolumeGPRSDownlink() != null)
            result += obj.getDataVolumeGPRSDownlink();
        else
            result += "null";

        result += ",\r\n\t";
        result += "\"changeCondition\":" + obj.getChangeCondition();

        result += ",\r\n\t";
        result += "\"changeTime\":\"" + octetDateTimeToString(obj.getChangeTime().toString()) + "\"";

        result += ",\r\n\t";
        result += "\"failureHandlingContinue\":";
        if (obj.getFailureHandlingContinue() != null)
            result += obj.getFailureHandlingContinue();
        else
            result += "null";

        result += ",\r\n\t";
        result += "\"userLocationInformation\":";
        if (obj.getUserLocationInformation() != null)
            result += "\"" + obj.getUserLocationInformation() + "\"";
        else
            result += "null";

        result += ",\r\n\t";
        result += "\"ePCQoSInformation\":";
        if (obj.getEPCQoSInformation() != null)
            result += EPCQoSInformationToString(obj.getEPCQoSInformation());
        else
            result += "null";

        result += ",\r\n\t";
        result += "\"cPCIoTEPSOptimisationIndicator\":";
        if (obj.getCPCIoTEPSOptimisationIndicator() != null)
            result += obj.getCPCIoTEPSOptimisationIndicator();
        else
            result += "null";

        result += ",\r\n\t";
        result += "\"servingPLMNRateControl\":";
        if (obj.getServingPLMNRateControl() != null)
            result += ServingPLMNRateControlToString(obj.getServingPLMNRateControl());
        else
            result += "null";

        return result + "\t}";
    }

    public static String ManagementExtensionToString(ManagementExtension obj) {
        String result = "\t{";

        result += "\t\"identifier\":" + obj.getIdentifier() + ",";
        result += "\t\"significance\":" + obj.getSignificance() + ",";
        result += "\t\"information\":" + obj.getInformation();

        result += "\t}";
        return result;
    }

    public static String DiagnosticsToString(Diagnostics obj) {

        String result = "\t{";

        if (obj.getGsm0408Cause() != null)
            result += "\t\"gsm0408Cause\":" + obj.getGsm0408Cause();
        else if (obj.getGsm0902MapErrorValue() != null)
            result += "\t\"gsm0902MapErrorValue\":" + obj.getGsm0902MapErrorValue();
        else if (obj.getItuTQ767Cause() != null)
            result += "\t\"itu-tQ767Cause\":" + obj.getItuTQ767Cause();
        else if (obj.getNetworkSpecificCause() != null)
            result += "\t\"networkSpecificCause\":" + ManagementExtensionToString(obj.getNetworkSpecificCause());
        else if (obj.getManufacturerSpecificCause() != null)
            result += "\t\"manufacturerSpecificCause\":" + obj.getManufacturerSpecificCause();
        else if (obj.getPositionMethodFailureCause() != null)
            result += "\t\"positionMethodFailureCause\":" + obj.getPositionMethodFailureCause();
        else if (obj.getUnauthorizedLCSClientCause() != null)
            result += "\t\"unauthorizedLCSClientCause\":" + obj.getUnauthorizedLCSClientCause();

        result += "\t}";
        return result;
    }

    public static String ChangeTimeExtensionToString(ChangeTimeExtension obj) throws IOException {
        String result = "\t{";

        if (obj.getChangeTime() != null)
            result += "\t\"changeTime\":\"" + octetDateTimeToString(obj.getChangeTime().toString()) + "\",";
        else
            result += "\t\"changeTime\":null,";

        if (obj.getChangeTimeTimeZone() != null)
            result += "\t\"changeTimeTimeZone\":" + obj.getChangeTimeTimeZone();
        else
            result += "\t\"changeTimeTimeZone\":null";

        result += "\t}";

        return result;

    }

    public static String ServiceEventToString(ServiceEvent obj) throws IOException {
        String result = "{";

        if (obj.getServiceCode() != null)
            result += "\"serviceCode\":" + obj.getServiceCode() + ",";
        else
            result += "\"serviceCode\":null,";

        if (obj.getUplinkVolume() != null)
            result += "\"uplinkVolume\":" + obj.getUplinkVolume() + ",";
        else
            result += "\"uplinkVolume\":null,";

        if (obj.getDownlinkVolume() != null)
            result += "\"downlinkVolume\":" + obj.getDownlinkVolume() + ",";
        else
            result += "\"downlinkVolume\":null,";

        if (obj.getUsageduration() != null)
            result += "\"usageduration\":" + obj.getUsageduration() + ",";
        else
            result += "\"usageduration\":null,";

        if (obj.getUrl() != null)
            result += "\"url\":\"" + obj.getUrl() + "\",";
        else
            result += "\"url\":null,";

        if (obj.getChargingRuleBaseName() != null)
            result += "\"chargingRuleBaseName\":\"" + obj.getChargingRuleBaseName() + "\",";
        else
            result += "\"chargingRuleBaseName\":null,";

        if (obj.getRatingGroup() != null)
            result += "\"ratingGroup\":" + obj.getRatingGroup() + ",";
        else
            result += "\"ratingGroup\":null,";

        if (obj.getServiceIdentifier() != null)
            result += "\"serviceIdentifier\":" + obj.getServiceIdentifier() + ",";
        else
            result += "\"serviceIdentifier\":null,";

        if (obj.getLocalSequenceNumber() != null)
            result += "\"localSequenceNumber\":" + obj.getLocalSequenceNumber() + ",";
        else
            result += "\"localSequenceNumber\":null,";

        if (obj.getEnvelopeStartTime() != null)
            result += "\"envelopeStartTime\":\"" + octetDateTimeToString(obj.getEnvelopeStartTime().toString()) + "\",";
        else
            result += "\"envelopeStartTime\":null,";

        if (obj.getEnvelopeEndTime() != null)
            result += "\"envelopeEndTime\":\"" + octetDateTimeToString(obj.getEnvelopeEndTime().toString()) + "\",";
        else
            result += "\"envelopeEndTime\":null,";

        if (obj.getDuration() != null)
            result += "\"duration\":\"" + obj.getDuration() + "\",";
        else
            result += "\"duration\":null,";

        if (obj.getChangeTimeTimeZone() != null)
            result += "\"changeTimeTimeZone\":" + obj.getChangeTimeTimeZone() + ",";
        else
            result += "\"changeTimeTimeZone\":null,";

        if (obj.getNoOCSCreditControl() != null)
            result += "\"noOCSCreditControl\":" + obj.getNoOCSCreditControl() + ",";
        else
            result += "\"noOCSCreditControl\":null,";

        if (obj.getUplinkPacketNum() != null)
            result += "\"uplinkPacketNum\":" + obj.getUplinkPacketNum() + ",";
        else
            result += "\"uplinkPacketNum\":null,";

        if (obj.getDownlinkPacketNum() != null)
            result += "\"downlinkPacketNum\":" + obj.getDownlinkPacketNum();
        else
            result += "\"downlinkPacketNum\":null";

        result += "}";

        return result;

    }

    public static String ContentInfoToStringJson(ContentInfo obj) throws IOException {
        String result = "{";

        result += "\"extensionType\":" + obj.getExtensionType() + ",";

        result += "\"length\":" + obj.getLengthh() + ",";

        result += "\"serviceList\":[";

        if (obj.getServiceList() != null) {

            List<ServiceEvent> lst = obj.getServiceList().getServiceEvent();
            int lst_size = lst.size();

            for (int i = 0; i < lst_size; i++) {
                result += ServiceEventToString(lst.get(i));

                if ((i + 1) < lst_size)
                    result += ",";
            }
        }

        result += "],";

        result += "\"changeTimeList\":[";
        if (obj.getChangeTimeList() != null) {
            List<ChangeTimeExtension> lst = obj.getChangeTimeList().getChangeTimeExtension();
            int lst_size = lst.size();

            for (int i = 0; i < lst.size(); i++) {
                result += ChangeTimeExtensionToString(lst.get(i));
                if ((i + 1) < lst_size)
                    result += ",";
            }
        }

        result += "],";

        if (obj.getRecordOpeningTime() != null)
            result += "\"recordOpeningTime\":\"" + octetDateTimeToString(obj.getRecordOpeningTime().toString()) + "\",";
        else
            result += "\"recordOpeningTime\":null,";

        if (obj.getDuration() != null)
            result += "\"duration\":\"" + obj.getDuration() + "\",";
        else
            result += "\"duration\":null,";

        if (obj.getTransparentVSA() != null)
            result += "\"transparentVSA\":\"" + obj.getTransparentVSA() + "\",";
        else
            result += "\"transparentVSA\":null,";

        if (obj.getCdrType() != null)
            result += "\"cdrType\":" + obj.getCdrType() + ",";
        else
            result += "\"cdrType\":null,";

        if (obj.getCreateTime() != null)
            result += "\"createTime\":" + octetDateTimeToString(obj.getCreateTime().toString()) + ",";
        else
            result += "\"createTime\":null,";

        if (obj.getChargingType() != null)
            result += "\"chargingType\":" + obj.getChargingType() + ",";
        else
            result += "\"chargingType\":null,";

        if (obj.getRoaming() != null)
            result += "\"roaming\":" + obj.getRoaming() + ",";
        else
            result += "\"roaming\":null,";

        if (obj.getProfile() != null)
            result += "\"profile\":" + obj.getProfile() + ",";
        else
            result += "\"profile\":null,";

        if (obj.getNsapi() != null)
            result += "\"nsapi\":" + obj.getNsapi() + ",";
        else
            result += "\"nsapi\":null,";

        if (obj.getLastActivityTimeUpLink() != null)
            result += "\"lastActivityTimeUpLink\":\"" + obj.getLastActivityTimeUpLink() + "\",";
        else
            result += "\"lastActivityTimeUpLink\":null,";

        if (obj.getLastActivityTimeDownLink() != null)
            result += "\"lastActivityTimeDownLink\":\"" + obj.getLastActivityTimeDownLink() + "\",";
        else
            result += "\"lastActivityTimeDownLink\":null,";

        if (obj.getZoneId() != null)
            result += "\"zoneId\":" + obj.getZoneId() + ",";
        else
            result += "\"zoneId\":null,";

        if (obj.getDaylightSavingTime() != null)
            result += "\"daylightSavingTime\":" + obj.getDaylightSavingTime() + ",";
        else
            result += "\"daylightSavingTime\":null,";

        if (obj.getLocalTimeZone() != null)
            result += "\"localTimeZone\":" + obj.getLocalTimeZone() + ",";
        else
            result += "\"localTimeZone\":null,";

        if (obj.getSgsnChange() != null)
            result += "\"sgsnChange\":" + obj.getSgsnChange() + ",";
        else
            result += "\"sgsnChange\":null,";

        if (obj.getSessionID() != null)
            result += "\"sessionID\":" + obj.getSessionID() + ",";
        else
            result += "\"sessionID\":null,";

        if (obj.getRecordOpeningTimeZone() != null)
            result += "\"recordOpeningTimeZone\":" + obj.getRecordOpeningTimeZone() + ",";
        else
            result += "\"recordOpeningTimeZone\":null,";

        if (obj.getSaRecordChangeTime() != null)
            result += "\"saRecordChangeTime\":\"" + octetDateTimeToString(obj.getSaRecordChangeTime().toString())
                    + "\",";
        else
            result += "\"saRecordChangeTime\":null,";

        if (obj.getSaRecordChangeTimeZone() != null)
            result += "\"saRecordChangeTimeZone\":" + obj.getSaRecordChangeTimeZone() + ",";
        else
            result += "\"saRecordChangeTimeZone\":null,";

        if (obj.getAcctSessionId() != null)
            result += "\"acctSessionId\":\"" + obj.getAcctSessionId() + "\",";
        else
            result += "\"acctSessionId\":null,";

        if (obj.getAcctTerminateCause() != null)
            result += "\"acctTerminateCause\":" + obj.getAcctTerminateCause();
        else
            result += "\"acctTerminateCause\":null";

        result += "}";

        return result;

    }

    public static String PSFurnishChargingInformationtoString(PSFurnishChargingInformation obj) {
        String result = "{";

        if (obj.getPSFreeFormatData() != null)
            result += "\"pSFreeFormatData\":\"" + obj.getPSFreeFormatData() + "\",";
        else
            result += "\"pSFreeFormatData\":null,";

        if (obj.getPSFFDAppendIndicator() != null)
            result += "\"pSFFDAppendIndicator\":" + obj.getPSFFDAppendIndicator();
        else
            result += "\"pSFFDAppendIndicator\":null";

        result += "}";
        return result;

    }

    public static String MOExceptionDataCounterToString(MOExceptionDataCounter obj) {

        String result = "{";

        result += "\"counterValue\":" + obj.getCounterValue() + ",";

        if (obj.getCounterTimestamp() != null)
            result += "\"counterTimestamp\":\"" + obj.getCounterTimestamp() + "\"";
        else
            result += "\"counterTimestamp\":null";
        result += "}";
        return result;
    }

    ///////////////////////////////////////////////////////////////////////////////////////////

    public static String ChangeOfServiceConditionsToString(ChangeOfServiceConditions obj) throws IOException {
        String result = "{";

        result += "\"ratingGroup\":" + obj.getRatingGroup();

        result += ",\r\n";
        result += "\"chargingRuleBaseName\":";
        if (obj.getChargingRuleBaseName() != null)
            result += "\"" + obj.getChargingRuleBaseName() + "\"";
        else
            result += "null";

        result += ",\r\n";
        result += "\"resultCode\":" + obj.getResultCode();

        result += ",\r\n";
        result += "\"localSequenceNumber\":" + obj.getLocalSequenceNumber();

        result += ",\r\n";
        result += "\"timeOfFirstUsage\":";
        if (obj.getTimeOfFirstUsage() != null)
            result += "\"" + octetDateTimeToString(obj.getTimeOfFirstUsage().toString()) + "\"";
        else
            result += "null";

        result += ",\r\n";
        result += "\"timeOfLastUsage\":";
        if (obj.getTimeOfLastUsage() != null)
            result += "\"" + octetDateTimeToString(obj.getTimeOfLastUsage().toString()) + "\"";
        else
            result += "null";

        result += ",\r\n";
        result += "\"timeUsage\":" + obj.getLocalSequenceNumber();

        result += ",\r\n";
        result += "\"serviceConditionChange???????????\":" + "\"" + obj.getServiceConditionChange() + "\"";

        result += ",\r\n";
        result += "\"qoSInformationNeg\":";
        if (obj.getQoSInformationNeg() != null)
            result += EPCQoSInformationToString(obj.getQoSInformationNeg());
        else
            result += "null";

        result += ",\r\n";
        result += "\"sgsnAddress\":";
        if (obj.getSgsnAddress() != null)
            result += GSNAddressToStringJson(obj.getSgsnAddress());
        else
            result += "null";

        result += ",\r\n";
        result += "\"sGSNPLMNIdentifier\":";
        if (obj.getSGSNPLMNIdentifier() != null)
            result += "{\"MCC\":" + TBCDStringToString(obj.getSGSNPLMNIdentifier().toString().substring(0, 4))
                    + ",\"MNC\":" + TBCDStringToString(obj.getSGSNPLMNIdentifier().toString().substring(4, 6)) + "}";
        else
            result += "null";

        result += ",\r\n";
        result += "\"datavolumeFBCUplink\":" + "\"" + obj.getDatavolumeFBCUplink() + "\"";

        result += ",\r\n";
        result += "\"datavolumeFBCDownlink\":" + "\"" + obj.getDatavolumeFBCDownlink() + "\"";

        result += ",\r\n";
        result += "\"timeOfReport\":";
        if (obj.getTimeOfReport() != null)
            result += "\"" + octetDateTimeToString(obj.getTimeOfReport().toString()) + "\"";
        else
            result += "null";

        result += ",\r\n";
        result += "\"rATType\":" + obj.getRATType();

        result += ",\r\n";
        result += "\"failureHandlingContinue\":" + obj.getFailureHandlingContinue();

        result += ",\r\n";
        result += "\"serviceIdentifier\":" + obj.getServiceIdentifier();

        result += ",\r\n";
        result += "\"pSFurnishChargingInformation\":";
        if (obj.getPSFurnishChargingInformation() != null)
            result += PSFurnishChargingInformationtoString(obj.getPSFurnishChargingInformation());
        else
            result += "null";

        result += ",\r\n";
        result += "\"aFRecordInformation\":[";

        if (obj.getAFRecordInformation() != null) {

            List<AFRecordInformation> lst = obj.getAFRecordInformation().getAFRecordInformation();
            int lst_size = lst.size();

            for (int i = 0; i < lst.size(); i++) {
                result += AFRecordInformationToString(lst.get(i));
                if ((i + 1) < lst_size)
                    result += ",";
            }
        }

        result += "]";

        result += ",\r\n";
        result += "\"userLocationInformation\":";
        if (obj.getUserLocationInformation() != null)
            result += "\"" + obj.getUserLocationInformation() + "\"";
        else
            result += "null";

        result += ",\r\n";
        result += "\"eventBasedChargingInformation\":";
        if (obj.getEventBasedChargingInformation() != null)
            result += EventBasedChargingInformationToString(obj.getEventBasedChargingInformation());
        else
            result += "null";

        result += ",\r\n";
        result += "\"timeQuotaMechanism\":";
        if (obj.getTimeQuotaMechanism() != null)
            result += TimeQuotaMechanismToString(obj.getTimeQuotaMechanism());
        else
            result += "null";

        result += ",\r\n";
        result += "\"serviceSpecificInfo\":[";

        if (obj.getServiceSpecificInfo() != null) {

            List<ServiceSpecificInfo> lst = obj.getServiceSpecificInfo().getServiceSpecificInfo();
            int lst_size = lst.size();

            for (int i = 0; i < lst.size(); i++) {
                result += ServiceSpecificInfoToString(lst.get(i));
                if ((i + 1) < lst_size)
                    result += ",";
            }
        }

        result += "]";

        result += ",\r\n";
        result += "\"threeGPP2UserLocationInformation\":";
        if (obj.getThreeGPP2UserLocationInformation() != null)
            result += "\"" + obj.getThreeGPP2UserLocationInformation() + "\"";
        else
            result += "null";

        result += ",\r\n";
        result += "\"servingPLMNRateControl\":";
        if (obj.getServingPLMNRateControl() != null)
            result += ServingPLMNRateControlToString(obj.getServingPLMNRateControl());
        else
            result += "null";

        result += ",\r\n";
        result += "\"aPNRateControl\":";
        if (obj.getAPNRateControl() != null)
            result += APNRateControlToString(obj.getAPNRateControl());
        else
            result += "null";

        result += "}";
        return result;

    }

    public static String AFRecordInformationToString(AFRecordInformation obj) {
        String result = "{";

        result += "\"aFChargingIdentifier\":\"" + obj.getAFChargingIdentifier() + "\",";

        if (obj.getFlows() != null)
            result += "\"flows\":" + FlowsToString(obj.getFlows());
        else
            result += "\"flows\":null";

        result += "}";

        return result;

    }

    public static String FlowsToString(Flows obj) {
        String result = "{";

        result += "\"mediaComponentNumber\":" + obj.getMediaComponentNumber();

        result += ",\r\n";
        result += "\"flowNumber\":[";

        if (obj.getFlowNumber() != null) {

            List<BerInteger> lst = obj.getFlowNumber().getBerInteger();
            int lst_size = lst.size();

            for (int i = 0; i < lst.size(); i++) {
                result += lst.get(i);
                if ((i + 1) < lst_size)
                    result += ",";
            }
        }

        result += "]}";

        return result;

    }

    public static String EventBasedChargingInformationToString(EventBasedChargingInformation obj) {
        String result = "{";

        result += "\"numberOfEvents\":\"" + obj.getNumberOfEvents() + "\",";
        result += "\"eventTimeStamps\":[";

        if (obj.getEventTimeStamps() != null) {

            List<BerOctetString> lst = obj.getEventTimeStamps().getBerOctetString();
            int lst_size = lst.size();

            for (int i = 0; i < lst.size(); i++) {
                result += "\"" + lst.get(i) + "\"";
                if ((i + 1) < lst_size)
                    result += ",";
            }
        }

        result += "]}";

        return result;
    }

    public static String TimeQuotaMechanismToString(TimeQuotaMechanism obj) {
        String result = "{";

        result += "\"timeQuotaType\":" + obj.getTimeQuotaType();
        result += ",\r\n";
        result += "\"baseTimeInterval\":" + obj.getBaseTimeInterval();
        result += "}";

        return result;

    }

    public static String ServiceSpecificInfoToString(ServiceSpecificInfo obj) {
        String result = "{";

        result += "\"serviceSpecificData???????????\":";
        if (obj.getServiceSpecificData() != null)
            result += "\"" + obj.getServiceSpecificData() + "\"";

        result += ",\r\n";
        result += "\"serviceSpecificType\":" + obj.getServiceSpecificType();

        result += "}";

        return result;

    }

    public static String SubscriptionIDToString(SubscriptionID obj) {
        String result = "{";

        result += "\"subscriptionIDType\":" + obj.getSubscriptionIDType() + ",";
        result += "\"subscriptionIDData\":\"" + obj.getSubscriptionIDData() + "\"";

        result += "}";

        return result;

    }

    public static String UserCSGInformationToString(UserCSGInformation obj) {
        String result = "{";

        result += "\"cSGId\":\"" + obj.getCSGId() + "\",";
        result += "\"cSGAccessMode\":" + obj.getCSGAccessMode() + ",";

        // ?????????????????
        if (obj.getCSGMembershipIndication() != null)
            result += "\"cSGMembershipIndication??????\":" + obj.getCSGMembershipIndication();
        else
            result += "\"cSGMembershipIndication??????\":null";

        result += "}";

        return result;

    }

    public static String ServingPLMNRateControlToString(ServingPLMNRateControl obj) {
        String result = "{";

        result += "\"sPLMNDLRateControlValue\":" + obj.getSPLMNDLRateControlValue() + ",";
        result += "\"sPLMNULRateControlValue\":" + obj.getSPLMNULRateControlValue();

        result += "}";
        return result;
    }

    public static String APNRateControlToString(APNRateControl obj) {
        String result = "{}";

        result += "\"aPNRateControlUplink\":";
        if (obj.getAPNRateControlUplink() != null)
            result += APNRateControlParametersToString(obj.getAPNRateControlUplink());
        else
            result += "null";

        result += ",\r\n";
        result += "\"aPNRateControlDownlink\":";
        if (obj.getAPNRateControlDownlink() != null)
            result += APNRateControlParametersToString(obj.getAPNRateControlDownlink());
        else
            result += "null";

        return result;

    }

    public static String APNRateControlParametersToString(APNRateControlParameters obj) {
        String result = "{";

        result += "\"additionalExceptionReports\":" + obj.getAdditionalExceptionReports();

        result += ",\r\n";
        result += "\"rateControlTimeUnit\":" + obj.getRateControlTimeUnit();

        result += ",\r\n";
        result += "\"rateControlMaxRate\":" + obj.getRateControlMaxRate();

        result += "}";

        return result;

    }
}
