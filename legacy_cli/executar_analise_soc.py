import subprocess
import sys
from datetime import datetime


def executar(comando):
    print(f"\n[+] Executando: {comando}")
    resultado = subprocess.run(comando, shell=True)

    if resultado.returncode != 0:
        print(f"[ERRO] Falha ao executar: {comando}")
        sys.exit(1)


def main():
    print("=" * 70)
    print("Wazuh + Suricata + IA - Análise SOC Automatizada")
    print(f"Início: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
    print("=" * 70)

    executar("python coletar_alertas.py")
    executar("python gerar_relatorio.py")
    executar("python analisar_com_ia.py")

    print("\n" + "=" * 70)
    print("[OK] Processo finalizado com sucesso.")
    print("Arquivos gerados:")
    print("- alertas_wazuh.json")
    print("- relatorio_soc.md")
    print("- relatorio_ia_soc.md")
    print("=" * 70)


if __name__ == "__main__":
    main()
