/*
 * This class file was automatically generated by ASN1bean v1.12.0 (http://www.beanit.com)
 */

package pgw;

import java.io.IOException;
import java.io.EOFException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;
import java.util.ArrayList;
import java.util.Iterator;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.io.Serializable;
import com.beanit.asn1bean.ber.*;
import com.beanit.asn1bean.ber.types.*;
import com.beanit.asn1bean.ber.types.string.*;


public class EPCQoSInformation implements BerType, Serializable {

	private static final long serialVersionUID = 1L;

	public static final BerTag tag = new BerTag(BerTag.UNIVERSAL_CLASS, BerTag.CONSTRUCTED, 16);

	private byte[] code = null;
	private BerInteger qCI = null;
	private BerInteger maxRequestedBandwithUL = null;
	private BerInteger maxRequestedBandwithDL = null;
	private BerInteger guaranteedBitrateUL = null;
	private BerInteger guaranteedBitrateDL = null;
	private BerInteger aRP = null;
	private BerInteger aPNAggregateMaxBitrateUL = null;
	private BerInteger aPNAggregateMaxBitrateDL = null;
	
	public EPCQoSInformation() {
	}

	public EPCQoSInformation(byte[] code) {
		this.code = code;
	}

	public void setQCI(BerInteger qCI) {
		this.qCI = qCI;
	}

	public BerInteger getQCI() {
		return qCI;
	}

	public void setMaxRequestedBandwithUL(BerInteger maxRequestedBandwithUL) {
		this.maxRequestedBandwithUL = maxRequestedBandwithUL;
	}

	public BerInteger getMaxRequestedBandwithUL() {
		return maxRequestedBandwithUL;
	}

	public void setMaxRequestedBandwithDL(BerInteger maxRequestedBandwithDL) {
		this.maxRequestedBandwithDL = maxRequestedBandwithDL;
	}

	public BerInteger getMaxRequestedBandwithDL() {
		return maxRequestedBandwithDL;
	}

	public void setGuaranteedBitrateUL(BerInteger guaranteedBitrateUL) {
		this.guaranteedBitrateUL = guaranteedBitrateUL;
	}

	public BerInteger getGuaranteedBitrateUL() {
		return guaranteedBitrateUL;
	}

	public void setGuaranteedBitrateDL(BerInteger guaranteedBitrateDL) {
		this.guaranteedBitrateDL = guaranteedBitrateDL;
	}

	public BerInteger getGuaranteedBitrateDL() {
		return guaranteedBitrateDL;
	}

	public void setARP(BerInteger aRP) {
		this.aRP = aRP;
	}

	public BerInteger getARP() {
		return aRP;
	}

	public void setAPNAggregateMaxBitrateUL(BerInteger aPNAggregateMaxBitrateUL) {
		this.aPNAggregateMaxBitrateUL = aPNAggregateMaxBitrateUL;
	}

	public BerInteger getAPNAggregateMaxBitrateUL() {
		return aPNAggregateMaxBitrateUL;
	}

	public void setAPNAggregateMaxBitrateDL(BerInteger aPNAggregateMaxBitrateDL) {
		this.aPNAggregateMaxBitrateDL = aPNAggregateMaxBitrateDL;
	}

	public BerInteger getAPNAggregateMaxBitrateDL() {
		return aPNAggregateMaxBitrateDL;
	}

	@Override public int encode(OutputStream reverseOS) throws IOException {
		return encode(reverseOS, true);
	}

	public int encode(OutputStream reverseOS, boolean withTag) throws IOException {

		if (code != null) {
			reverseOS.write(code);
			if (withTag) {
				return tag.encode(reverseOS) + code.length;
			}
			return code.length;
		}

		int codeLength = 0;
		if (aPNAggregateMaxBitrateDL != null) {
			codeLength += aPNAggregateMaxBitrateDL.encode(reverseOS, false);
			// write tag: CONTEXT_CLASS, PRIMITIVE, 8
			reverseOS.write(0x88);
			codeLength += 1;
		}
		
		if (aPNAggregateMaxBitrateUL != null) {
			codeLength += aPNAggregateMaxBitrateUL.encode(reverseOS, false);
			// write tag: CONTEXT_CLASS, PRIMITIVE, 7
			reverseOS.write(0x87);
			codeLength += 1;
		}
		
		if (aRP != null) {
			codeLength += aRP.encode(reverseOS, false);
			// write tag: CONTEXT_CLASS, PRIMITIVE, 6
			reverseOS.write(0x86);
			codeLength += 1;
		}
		
		if (guaranteedBitrateDL != null) {
			codeLength += guaranteedBitrateDL.encode(reverseOS, false);
			// write tag: CONTEXT_CLASS, PRIMITIVE, 5
			reverseOS.write(0x85);
			codeLength += 1;
		}
		
		if (guaranteedBitrateUL != null) {
			codeLength += guaranteedBitrateUL.encode(reverseOS, false);
			// write tag: CONTEXT_CLASS, PRIMITIVE, 4
			reverseOS.write(0x84);
			codeLength += 1;
		}
		
		if (maxRequestedBandwithDL != null) {
			codeLength += maxRequestedBandwithDL.encode(reverseOS, false);
			// write tag: CONTEXT_CLASS, PRIMITIVE, 3
			reverseOS.write(0x83);
			codeLength += 1;
		}
		
		if (maxRequestedBandwithUL != null) {
			codeLength += maxRequestedBandwithUL.encode(reverseOS, false);
			// write tag: CONTEXT_CLASS, PRIMITIVE, 2
			reverseOS.write(0x82);
			codeLength += 1;
		}
		
		codeLength += qCI.encode(reverseOS, false);
		// write tag: CONTEXT_CLASS, PRIMITIVE, 1
		reverseOS.write(0x81);
		codeLength += 1;
		
		codeLength += BerLength.encodeLength(reverseOS, codeLength);

		if (withTag) {
			codeLength += tag.encode(reverseOS);
		}

		return codeLength;

	}

	@Override public int decode(InputStream is) throws IOException {
		return decode(is, true);
	}

	public int decode(InputStream is, boolean withTag) throws IOException {
		int tlByteCount = 0;
		int vByteCount = 0;
		BerTag berTag = new BerTag();

		if (withTag) {
			tlByteCount += tag.decodeAndCheck(is);
		}

		BerLength length = new BerLength();
		tlByteCount += length.decode(is);
		int lengthVal = length.val;
		vByteCount += berTag.decode(is);

		if (berTag.equals(BerTag.CONTEXT_CLASS, BerTag.PRIMITIVE, 1)) {
			qCI = new BerInteger();
			vByteCount += qCI.decode(is, false);
			if (lengthVal >= 0 && vByteCount == lengthVal) {
				return tlByteCount + vByteCount;
			}
			vByteCount += berTag.decode(is);
		}
		else {
			throw new IOException("Tag does not match mandatory sequence component.");
		}
		
		if (berTag.equals(BerTag.CONTEXT_CLASS, BerTag.PRIMITIVE, 2)) {
			maxRequestedBandwithUL = new BerInteger();
			vByteCount += maxRequestedBandwithUL.decode(is, false);
			if (lengthVal >= 0 && vByteCount == lengthVal) {
				return tlByteCount + vByteCount;
			}
			vByteCount += berTag.decode(is);
		}
		
		if (berTag.equals(BerTag.CONTEXT_CLASS, BerTag.PRIMITIVE, 3)) {
			maxRequestedBandwithDL = new BerInteger();
			vByteCount += maxRequestedBandwithDL.decode(is, false);
			if (lengthVal >= 0 && vByteCount == lengthVal) {
				return tlByteCount + vByteCount;
			}
			vByteCount += berTag.decode(is);
		}
		
		if (berTag.equals(BerTag.CONTEXT_CLASS, BerTag.PRIMITIVE, 4)) {
			guaranteedBitrateUL = new BerInteger();
			vByteCount += guaranteedBitrateUL.decode(is, false);
			if (lengthVal >= 0 && vByteCount == lengthVal) {
				return tlByteCount + vByteCount;
			}
			vByteCount += berTag.decode(is);
		}
		
		if (berTag.equals(BerTag.CONTEXT_CLASS, BerTag.PRIMITIVE, 5)) {
			guaranteedBitrateDL = new BerInteger();
			vByteCount += guaranteedBitrateDL.decode(is, false);
			if (lengthVal >= 0 && vByteCount == lengthVal) {
				return tlByteCount + vByteCount;
			}
			vByteCount += berTag.decode(is);
		}
		
		if (berTag.equals(BerTag.CONTEXT_CLASS, BerTag.PRIMITIVE, 6)) {
			aRP = new BerInteger();
			vByteCount += aRP.decode(is, false);
			if (lengthVal >= 0 && vByteCount == lengthVal) {
				return tlByteCount + vByteCount;
			}
			vByteCount += berTag.decode(is);
		}
		
		if (berTag.equals(BerTag.CONTEXT_CLASS, BerTag.PRIMITIVE, 7)) {
			aPNAggregateMaxBitrateUL = new BerInteger();
			vByteCount += aPNAggregateMaxBitrateUL.decode(is, false);
			if (lengthVal >= 0 && vByteCount == lengthVal) {
				return tlByteCount + vByteCount;
			}
			vByteCount += berTag.decode(is);
		}
		
		if (berTag.equals(BerTag.CONTEXT_CLASS, BerTag.PRIMITIVE, 8)) {
			aPNAggregateMaxBitrateDL = new BerInteger();
			vByteCount += aPNAggregateMaxBitrateDL.decode(is, false);
			if (lengthVal >= 0 && vByteCount == lengthVal) {
				return tlByteCount + vByteCount;
			}
			vByteCount += berTag.decode(is);
		}
		
		if (lengthVal < 0) {
			if (!berTag.equals(0, 0, 0)) {
				throw new IOException("Decoded sequence has wrong end of contents octets");
			}
			vByteCount += BerLength.readEocByte(is);
			return tlByteCount + vByteCount;
		}

		throw new IOException("Unexpected end of sequence, length tag: " + lengthVal + ", bytes decoded: " + vByteCount);

	}

	public void encodeAndSave(int encodingSizeGuess) throws IOException {
		ReverseByteArrayOutputStream reverseOS = new ReverseByteArrayOutputStream(encodingSizeGuess);
		encode(reverseOS, false);
		code = reverseOS.getArray();
	}

	@Override public String toString() {
		StringBuilder sb = new StringBuilder();
		appendAsString(sb, 0);
		return sb.toString();
	}

	public void appendAsString(StringBuilder sb, int indentLevel) {

		sb.append("{");
		sb.append("\n");
		for (int i = 0; i < indentLevel + 1; i++) {
			sb.append("\t");
		}
		if (qCI != null) {
			sb.append("qCI: ").append(qCI);
		}
		else {
			sb.append("qCI: <empty-required-field>");
		}
		
		if (maxRequestedBandwithUL != null) {
			sb.append(",\n");
			for (int i = 0; i < indentLevel + 1; i++) {
				sb.append("\t");
			}
			sb.append("maxRequestedBandwithUL: ").append(maxRequestedBandwithUL);
		}
		
		if (maxRequestedBandwithDL != null) {
			sb.append(",\n");
			for (int i = 0; i < indentLevel + 1; i++) {
				sb.append("\t");
			}
			sb.append("maxRequestedBandwithDL: ").append(maxRequestedBandwithDL);
		}
		
		if (guaranteedBitrateUL != null) {
			sb.append(",\n");
			for (int i = 0; i < indentLevel + 1; i++) {
				sb.append("\t");
			}
			sb.append("guaranteedBitrateUL: ").append(guaranteedBitrateUL);
		}
		
		if (guaranteedBitrateDL != null) {
			sb.append(",\n");
			for (int i = 0; i < indentLevel + 1; i++) {
				sb.append("\t");
			}
			sb.append("guaranteedBitrateDL: ").append(guaranteedBitrateDL);
		}
		
		if (aRP != null) {
			sb.append(",\n");
			for (int i = 0; i < indentLevel + 1; i++) {
				sb.append("\t");
			}
			sb.append("aRP: ").append(aRP);
		}
		
		if (aPNAggregateMaxBitrateUL != null) {
			sb.append(",\n");
			for (int i = 0; i < indentLevel + 1; i++) {
				sb.append("\t");
			}
			sb.append("aPNAggregateMaxBitrateUL: ").append(aPNAggregateMaxBitrateUL);
		}
		
		if (aPNAggregateMaxBitrateDL != null) {
			sb.append(",\n");
			for (int i = 0; i < indentLevel + 1; i++) {
				sb.append("\t");
			}
			sb.append("aPNAggregateMaxBitrateDL: ").append(aPNAggregateMaxBitrateDL);
		}
		
		sb.append("\n");
		for (int i = 0; i < indentLevel; i++) {
			sb.append("\t");
		}
		sb.append("}");
	}

}

