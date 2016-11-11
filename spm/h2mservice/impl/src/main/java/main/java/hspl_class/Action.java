//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.7 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2016.02.29 at 10:28:31 AM CET 
//


package main.java.hspl_class;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for action.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="action">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="authorise_access"/>
 *     &lt;enumeration value="no_authorise_access"/>
 *     &lt;enumeration value="enable"/>
 *     &lt;enumeration value="remove"/>
 *     &lt;enumeration value="reduce"/>
 *     &lt;enumeration value="check_over"/>
 *     &lt;enumeration value="count"/>
 *     &lt;enumeration value="prot_conf"/>
 *     &lt;enumeration value="prot_integr"/>
 *     &lt;enumeration value="prot_conf_integr"/>
 *     &lt;enumeration value="compress"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "action")
@XmlEnum
public enum Action {

    @XmlEnumValue("authorise_access")
    AUTHORISE_ACCESS("authorise_access"),
    @XmlEnumValue("no_authorise_access")
    NO_AUTHORISE_ACCESS("no_authorise_access"),
    @XmlEnumValue("enable")
    ENABLE("enable"),
    @XmlEnumValue("remove")
    REMOVE("remove"),
    @XmlEnumValue("reduce")
    REDUCE("reduce"),
    @XmlEnumValue("check_over")
    CHECK_OVER("check_over"),
    @XmlEnumValue("count")
    COUNT("count"),
    @XmlEnumValue("prot_conf")
    PROT_CONF("prot_conf"),
    @XmlEnumValue("prot_integr")
    PROT_INTEGR("prot_integr"),
    @XmlEnumValue("prot_conf_integr")
    PROT_CONF_INTEGR("prot_conf_integr"),
    @XmlEnumValue("compress")
    COMPRESS("compress");
    private final String value;

    Action(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static Action fromValue(String v) {
        for (Action c: Action.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}