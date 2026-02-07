# ARP Poisoning Man-in-the-Middle Attack 🔴

## Análisis de Vulnerabilidades en Capa 2 del Modelo OSI

**Autor:** Branyel Estifenso Pérez Díaz  
**Materia:** Seguridad de Redes - Proyecto Final

---

## 📋 Introducción

Este proyecto demuestra el ataque de **ARP Poisoning (Envenenamiento de Caché ARP)** para posicionarse como **Man-in-the-Middle (MitM)** e interceptar tráfico entre dispositivos en una red local.

### Vulnerabilidad ARP

El protocolo ARP (Address Resolution Protocol) opera en la **Capa 2 del modelo OSI** y carece de mecanismos de autenticación nativos. Esto permite que un atacante envíe respuestas ARP falsificadas para:

- Asociar su dirección MAC con la IP del gateway
- Interceptar todo el tráfico de la víctima
- Realizar ataques de tipo Man-in-the-Middle

---

## 🌐 Topología del Laboratorio

```
┌────────────────────────────────────────────────────────────────────────────┐
│                              EVE-NG Lab                                     │
│                           Red: 14.89.0.0/24                                │
│                                                                            │
│   ┌─────────────────┐         ┌─────────────────┐         ┌──────────────┐ │
│   │   Gateway (R1)  │         │ Atacante (Kali) │         │ Víctima VPCS │ │
│   │   14.89.0.1     │◄───────►│   14.89.0.3     │◄───────►│  14.89.0.4   │ │
│   │ aa:bb:cc:00:20:00│         │00:50:00:00:01:00│         │00:77:00:00:01:01│
│   └─────────────────┘         └─────────────────┘         └──────────────┘ │
│                                      │                                      │
│                                      ▼                                      │
│                              [Switch L2]                                    │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

### Direccionamiento IP y MAC

| Dispositivo | Rol | Dirección IP | Dirección MAC |
|-------------|-----|--------------|---------------|
| **R1** | Gateway | 14.89.0.1 | aa:bb:cc:00:20:00 |
| **Kali Linux** | Atacante | 14.89.0.3 | 00:50:00:00:01:00 |
| **VPCS** | Víctima | 14.89.0.4 | 00:77:00:00:01:01 |

---

## 🔧 Funcionamiento del Ataque

### Paso 1: Estado Normal (Pre-Ataque)

```
VPCS ARP Cache:
14.89.0.1 → aa:bb:cc:00:20:00 (Gateway real)
```

### Paso 2: Envenenamiento ARP

El atacante envía paquetes ARP falsificados:
- A la **víctima**: "14.89.0.1 está en 00:50:00:00:01:00" (MAC del atacante)
- Al **gateway**: "14.89.0.4 está en 00:50:00:00:01:00" (MAC del atacante)

### Paso 3: Estado Después del Ataque

```
VPCS ARP Cache (POISONED):
14.89.0.1 → 00:50:00:00:01:00 (MAC del ATACANTE!)
```

Ahora todo el tráfico de la víctima hacia el gateway pasa por el atacante.

---

## ⚠️ Paso Crítico: Habilitar IP Forwarding

**IMPORTANTE:** Antes de ejecutar el ataque, es **obligatorio** habilitar el reenvío de IP en el atacante. Sin esto, la víctima perderá conectividad.

```bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```

### Verificar estado
```bash
cat /proc/sys/net/ipv4/ip_forward
# Debe mostrar: 1
```

### Hacer permanente (opcional)
```bash
# Editar /etc/sysctl.conf y agregar:
net.ipv4.ip_forward = 1

# Aplicar cambios:
sudo sysctl -p
```

---

## 📦 Requisitos

### Software
- Python 3.x
- Scapy (biblioteca de manipulación de paquetes)
- Sistema operativo Linux (preferiblemente Kali Linux)

### Permisos
```bash
# Se requieren permisos de superusuario (root)
sudo python3 MitM_Attack.py
```

### Instalación de dependencias
```bash
pip install -r requirements.txt
```

---

## 🚀 Uso

### Habilitar IP Forwarding (obligatorio)
```bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```

### Ejecución del ataque
```bash
sudo python3 MitM_Attack.py -t 14.89.0.4 -g 14.89.0.1 -i eth0
```

### Parámetros
| Opción | Descripción |
|--------|-------------|
| `-t, --target` | IP de la víctima (14.89.0.4) |
| `-g, --gateway` | IP del gateway (14.89.0.1) |
| `-i, --interface` | Interfaz de red (eth0) |
| `-c, --continuous` | Modo continuo (re-envenenamiento periódico) |

---

## ✅ Validación del Ataque

### En la máquina víctima (VPCS)

Verificar la caché ARP:
```
VPCS> show arp
```

**Resultado esperado (ANTES del ataque):**
```
14.89.0.1   aa:bb:cc:00:20:00   expires in 115 seconds
```

**Resultado esperado (DESPUÉS del ataque - ENVENENADO):**
```
14.89.0.1   00:50:00:00:01:00   expires in 115 seconds
```

⚠️ **Nota:** La MAC del gateway ahora muestra la MAC del atacante (`00:50:00:00:01:00`)

### En el router gateway (R1)

```cisco
R1# show ip arp
```

Verificar que la entrada de la víctima también muestra la MAC del atacante.

### En Kali (Atacante)

Capturar tráfico interceptado:
```bash
sudo tcpdump -i eth0 -vvv
```

O usar Wireshark para análisis detallado:
```bash
sudo wireshark &
```

---

## 🛡️ Mitigación

### 1. Dynamic ARP Inspection (DAI)

DAI valida los paquetes ARP contra una base de datos de DHCP Snooping.

```cisco
! Habilitar DHCP Snooping primero
Switch(config)# ip dhcp snooping
Switch(config)# ip dhcp snooping vlan 10

! Configurar puerto confiable (uplink al DHCP server)
Switch(config)# interface GigabitEthernet0/1
Switch(config-if)# ip dhcp snooping trust

! Habilitar DAI
Switch(config)# ip arp inspection vlan 10

! Configurar puerto confiable para DAI
Switch(config)# interface GigabitEthernet0/1
Switch(config-if)# ip arp inspection trust
```

### 2. DHCP Snooping

Construye una tabla de binding IP-MAC legítima.

```cisco
Switch(config)# ip dhcp snooping
Switch(config)# ip dhcp snooping vlan 10,20,30

Switch(config)# interface GigabitEthernet0/1
Switch(config-if)# ip dhcp snooping trust

Switch(config)# interface range GigabitEthernet0/2-24
Switch(config-if-range)# ip dhcp snooping limit rate 10
```

### 3. Port Security

Limita las direcciones MAC por puerto.

```cisco
Switch(config)# interface GigabitEthernet0/2
Switch(config-if)# switchport mode access
Switch(config-if)# switchport port-security
Switch(config-if)# switchport port-security maximum 2
Switch(config-if)# switchport port-security mac-address sticky
Switch(config-if)# switchport port-security violation shutdown
```

### 4. ARP Estáticas (para entornos pequeños)

```cisco
! En el switch o router
Switch(config)# arp 14.89.0.4 00:77:00:00:01:01 arpa

! En hosts Linux
sudo arp -s 14.89.0.1 aa:bb:cc:00:20:00
```

### Resumen de Mitigaciones

| Técnica | Descripción | Efectividad |
|---------|-------------|-------------|
| **DAI** | Valida paquetes ARP contra DHCP Snooping | ⭐⭐⭐⭐⭐ |
| **DHCP Snooping** | Crea binding IP-MAC legítimo | ⭐⭐⭐⭐⭐ |
| **Port Security** | Limita MACs por puerto | ⭐⭐⭐⭐ |
| **ARP Estáticas** | Entradas ARP manuales | ⭐⭐⭐ |
| **VLANs** | Segmentación de red | ⭐⭐⭐ |
| **802.1X** | Autenticación de puerto | ⭐⭐⭐⭐⭐ |

---

## ⚠️ Advertencia Legal

**Este script es únicamente para propósitos educativos y de investigación.**

El uso de esta herramienta contra redes sin autorización explícita es **ilegal** y puede resultar en:
- Cargos criminales bajo leyes de cibercrimen
- Responsabilidad civil por daños
- Expulsión académica o despido laboral

**Solo utilizar en entornos de laboratorio controlados con autorización.**

---

## 📚 Referencias

- [ARP Protocol - RFC 826](https://tools.ietf.org/html/rfc826)
- [Dynamic ARP Inspection - Cisco](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst6500/ios/12-2SX/configuration/guide/book/dynarp.html)
- [DHCP Snooping - Cisco](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst4500/12-2/25ew/configuration/guide/conf/dhcp.html)
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Man-in-the-Middle Attack - OWASP](https://owasp.org/www-community/attacks/Man-in-the-middle_attack)

---

## 📄 Licencia

Este proyecto está bajo la licencia MIT - ver el archivo [LICENSE](LICENSE) para más detalles.

---

**Universidad:** [Nombre de la Universidad]  
**Fecha:** 2026
