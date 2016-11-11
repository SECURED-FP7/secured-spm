//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.7 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2016.04.19 at 01:07:32 PM CEST 
//


package main.java.associationList_class;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlID;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.CollapsedStringAdapter;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;


/**
 * <p>Java class for association complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="association">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="IP" type="{http://www.example.org/AssociationList}IP" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element name="URI" type="{http://www.example.org/AssociationList}URI" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element name="RE" type="{http://www.example.org/AssociationList}RE" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element name="Event" type="{http://www.example.org/AssociationList}event" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element name="Mime-type" type="{http://www.example.org/AssociationList}Mime-type" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element name="VPN" type="{http://www.example.org/AssociationList}VPN" maxOccurs="unbounded" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute name="Name" type="{http://www.w3.org/2001/XMLSchema}ID" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "association", propOrder = {
    "ip",
    "uri",
    "re",
    "event",
    "mimeType",
    "vpn"
})
public class Association {

    @XmlElement(name = "IP")
    protected List<IP> ip;
    @XmlElement(name = "URI")
    protected List<URI> uri;
    @XmlElement(name = "RE")
    protected List<RE> re;
    @XmlElement(name = "Event")
    protected List<Event> event;
    @XmlElement(name = "Mime-type")
    protected List<MimeType> mimeType;
    @XmlElement(name = "VPN")
    protected List<VPN> vpn;
    @XmlAttribute(name = "Name")
    @XmlJavaTypeAdapter(CollapsedStringAdapter.class)
    @XmlID
    @XmlSchemaType(name = "ID")
    protected String name;

    /**
     * Gets the value of the ip property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the ip property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getIP().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link IP }
     * 
     * 
     */
    public List<IP> getIP() {
        if (ip == null) {
            ip = new ArrayList<IP>();
        }
        return this.ip;
    }

    /**
     * Gets the value of the uri property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the uri property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getURI().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link URI }
     * 
     * 
     */
    public List<URI> getURI() {
        if (uri == null) {
            uri = new ArrayList<URI>();
        }
        return this.uri;
    }

    /**
     * Gets the value of the re property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the re property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getRE().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link RE }
     * 
     * 
     */
    public List<RE> getRE() {
        if (re == null) {
            re = new ArrayList<RE>();
        }
        return this.re;
    }

    /**
     * Gets the value of the event property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the event property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getEvent().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link Event }
     * 
     * 
     */
    public List<Event> getEvent() {
        if (event == null) {
            event = new ArrayList<Event>();
        }
        return this.event;
    }

    /**
     * Gets the value of the mimeType property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the mimeType property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getMimeType().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link MimeType }
     * 
     * 
     */
    public List<MimeType> getMimeType() {
        if (mimeType == null) {
            mimeType = new ArrayList<MimeType>();
        }
        return this.mimeType;
    }

    /**
     * Gets the value of the vpn property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the vpn property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getVPN().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link VPN }
     * 
     * 
     */
    public List<VPN> getVPN() {
        if (vpn == null) {
            vpn = new ArrayList<VPN>();
        }
        return this.vpn;
    }

    /**
     * Gets the value of the name property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getName() {
        return name;
    }

    /**
     * Sets the value of the name property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setName(String value) {
        this.name = value;
    }

}
