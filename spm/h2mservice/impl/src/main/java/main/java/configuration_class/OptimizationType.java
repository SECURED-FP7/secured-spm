//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.7
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a>
// Any modifications to this file will be lost upon recompilation of the source schema.
// Generated on: 2015.07.14 at 02:12:36 PM CEST
//


package main.java.configuration_class;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for optimizationType.
 *
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="optimizationType">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="minTranferCostminLatency"/>
 *     &lt;enumeration value="minBuyCostminLatency"/>
 *     &lt;enumeration value="minBuyCostmaxRating"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 *
 */
@XmlType(name = "optimizationType")
@XmlEnum
public enum OptimizationType {

    @XmlEnumValue("minTranferCostminLatency")
    MIN_TRANFER_COSTMIN_LATENCY("minTranferCostminLatency"),
    @XmlEnumValue("minBuyCostminLatency")
    MIN_BUY_COSTMIN_LATENCY("minBuyCostminLatency"),
    @XmlEnumValue("minBuyCostmaxRating")
    MIN_BUY_COSTMAX_RATING("minBuyCostmaxRating");
    private final String value;

    OptimizationType(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static OptimizationType fromValue(String v) {
        for (OptimizationType c: OptimizationType.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}