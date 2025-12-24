# TON Lottery Bot

Bot de Telegram para gestionar una lotería basada en TON.  
Cada usuario obtiene una wallet interna de depósito en TON, puede comprar boletos de rifas activas y retirar sus premios a una dirección externa de TON.

## Características

- Registro automático de jugadores con enlace de referido.
- Wallet interna por usuario (custodial) en TON.
- Depósitos automáticos: el bot detecta depósitos en la dirección interna del jugador y acredita saldo.
- Creación de rifas por administradores:
  - Nombre de la rifa.
  - Cantidad de números que juegan.
  - Precio por boleto.
  - Configuración de premios por número ganador (porcentaje del pozo).
  - Varias rifas simultáneas.
- Compra de boletos:
  - Botón “🎫 Buy Ticket”.
  - Asignación automática de números disponibles.
  - Cálculo de probabilidad de ganar según boletos comprados.
- Ejecución automática de la rifa al venderse el último boleto:
  - Cálculo del pozo.
  - Reparto de premios según configuración.
  - Acreditación de premios al saldo interno de los ganadores.
  - Notificación por mensaje a los participantes.
- Retiros:
  - El usuario registra una sola vez su dirección de pago TON (`/set_payout`).
  - Retiro con comando `/withdraw` limitado a enteros o un decimal (ej. `1`, `1.5` TON).
  - Worker de retiros que envía las transacciones desde la wallet interna.
- Menú principal con teclado de respuesta:
  - 👥 Referral – enlace de referido.
  - ➕ Add Balance – ver dirección de depósito.
  - 💰 My Balance – ver saldo interno.
  - 🏆 Withdraw – retirar premios.
  - 🎫 Buy Ticket – entrar a loterías activas y comprar boletos.

## Requisitos

- Python 3.10 o superior.
- Cuenta de Telegram y un bot creado con [BotFather](https://t.me/BotFather).
- API de TON compatible (por ejemplo, [TON Center](https://toncenter.com/)) para:
  - Consultar información de wallets.
  - Leer transacciones.
  - Enviar BOC (transacciones firmadas).

## Instalación

### 1. Clonar el repositorio

```bash
git clone https://github.com/tu-usuario/usdt-lottery-bot.git
cd TU DIRECTORIO
