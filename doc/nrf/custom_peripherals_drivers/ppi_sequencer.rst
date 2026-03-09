.. _ppi_sequencer:

PPI Sequencer
#############

.. contents::
   :local:
   :depth: 2

Overview
********

The PPI Sequencer library (``ppi_seq``) uses hardware PPI (Programmable Peripheral Interconnect) connections to periodically trigger peripheral tasks, such as SPIM or TWIM transfers, entirely in hardware, without waking the CPU after each individual operation.
The application is only notified once a configurable *batch* of operations has completed.

This makes the library particularly well suited for **periodic sensor data collection** where samples can be accumulated and processed together, minimising CPU wake-ups and NVM accesses.

Key concepts:

* **Period**: the interval between consecutive task triggers, in microseconds.
* **Batch**: a fixed number of periods after which the application callback fires.
* **Task**: the hardware peripheral task register address to trigger each period.
* **Extra ops**: optional additional tasks triggered within the same period at defined microsecond offsets.
* **Timing source**: the hardware clock that controls when the task fires (GRTC, RTC, or TIMER).
* **Notifier**: the mechanism used to signal the application when a batch completes (``k_timer`` or a TIMER counter).

A higher-level helper module, ``ppi_seq_i2c_spi``, wraps ``ppi_seq`` in a Zephyr device driver with devicetree support for I2C/SPI use cases.

Static Configuration
********************

Kconfig
=======

Enable the core library and optionally the I2C/SPI helper in your project's ``prj.conf``:

.. code-block:: kconfig

   # Core PPI sequencer library
   CONFIG_PPI_SEQ=y

   # I2C/SPI helper module (requires CONFIG_PPI_SEQ)
   CONFIG_PPI_SEQ_I2C_SPI=y

   # Maximum number of GPPI channel handles per sequencer instance.
   # Increase if using many extra ops.
   CONFIG_PPI_SEQ_MAX_PPI_HANDLES=8

Devicetree (``ppi_seq_i2c_spi``)
=================================

The ``ppi_seq_i2c_spi`` module is configured in the devicetree using the ``"nordic,ppi-seq-spi"`` or ``"nordic,ppi-seq-i2c"`` compatible strings.

Common properties shared by both bindings:

.. list-table::
   :header-rows: 1
   :widths: 20 10 70

   * - Property
     - Type
     - Description
   * - ``rtc``
     - phandle
     - RTC instance as timing source. Provides the lowest power consumption.
   * - ``timer``
     - phandle
     - TIMER instance as timing source. Provides the highest precision.
   * - ``timer_notifier``
     - phandle
     - TIMER instance for batch completion counting. If omitted, ``k_timer`` is used.
   * - ``extra_transfers``
     - array
     - Offsets in microseconds for additional transfers within each period. Requires ``rtc`` or ``timer``.

If neither ``rtc`` nor ``timer`` is specified, the GRTC interval channel is used as the timing source.

SPI-specific properties for ``"nordic,ppi-seq-spi"``:

.. list-table::
   :header-rows: 1
   :widths: 25 10 10 55

   * - Property
     - Type
     - Default
     - Description
   * - ``frequency``
     - int
     - required
     - SPI clock frequency in Hz.
   * - ``spi-cpol``
     - bool
     - false
     - Clock idle state is high when set.
   * - ``spi-cpha``
     - bool
     - false
     - Data is sampled on the second clock edge when set.
   * - ``spi-lsb-first``
     - bool
     - false
     - LSB-first bit order.
   * - ``spi-cs-high``
     - bool
     - false
     - Chip select is active-high.
   * - ``spi-cs-setup-delay-ns``
     - int
     - 1000
     - CS assert-to-transfer lead time in nanoseconds.

**Example — SPI with RTC timing source (lowest power):**

.. code-block:: dts

   &spi130 {
       compatible = "nordic,ppi-seq-spi";
       status = "okay";
       pinctrl-0 = <&spi130_default_alt>;
       pinctrl-1 = <&spi130_sleep_alt>;
       pinctrl-names = "default", "sleep";
       overrun-character = <0x00>;
       memory-regions = <&cpuapp_dma_region>;
       cs-gpios = <&gpio0 8 GPIO_ACTIVE_LOW>;
       frequency = <8000000>;
       rtc = <&rtc130>;
   };

**Example — SPI with TIMER timing source and extra transfers at +20 µs and +40 µs:**

.. code-block:: dts

   &spi130 {
       compatible = "nordic,ppi-seq-spi";
       status = "okay";
       /* ... pin control, memory-regions, cs-gpios ... */
       frequency = <4000000>;
       timer = <&timer20>;
       extra_transfers = <20 40>;
   };

**Example — I2C with GRTC timing (default, no explicit source needed):**

.. code-block:: dts

   &i2c130 {
       compatible = "nordic,ppi-seq-i2c";
       status = "okay";
       /* ... pin control ... */
       clock-frequency = <I2C_BITRATE_FAST>;
       /* No rtc or timer specified — GRTC interval channel is used automatically. */
   };

Runtime Configuration
*********************

Configuration of the low-level ``ppi_seq`` API is a three-step process performed at runtime.
All structures referenced by the sequencer at runtime **must have static storage duration**.

Step 1 — Configure the Notifier
================================

The notifier determines how the application is informed when a batch of operations completes.
Two notifier types are available.

Option A — System Timer (``k_timer``)
--------------------------------------

The ``k_timer`` notifier is recommended for periods of 1 ms or longer and when power consumption matters.
The timer fires approximately at the estimated end of the batch.

.. code-block:: c

   static struct ppi_seq_notifier notifier;

   /* offset: duration of the last operation in microseconds.
    * Set to 0 if operations are short relative to the period. */
   notifier.type   = PPI_SEQ_NOTIFIER_SYS_TIMER;
   notifier.offset = 0;

.. note::

   The system timer adds a quarter-period safety margin to the expiry estimate.
   Do not use this notifier with a TIMER timing source, since TIMER is clocked from a different source than ``k_timer``.

Option B — TIMER in Counter Mode
----------------------------------

The TIMER counter notifier is recommended for periods shorter than approximately 500 µs, where ``k_timer`` jitter is unacceptable.
The TIMER counts completed operations via PPI and fires an interrupt immediately after the batch is done.
This mode costs approximately 5–10 µA of additional current.

.. code-block:: c

   static struct ppi_seq_notifier notifier;

   /* Wire the interrupt to the nrfx_timer handler. */
   IRQ_CONNECT(DT_IRQN(DT_NODELABEL(timer20)),
               DT_IRQ_BY_IDX(DT_NODELABEL(timer20), 0, priority),
               nrfx_timer_irq_handler, &notifier.nrfx_timer.timer, 0);

   notifier.type = PPI_SEQ_NOTIFIER_NRFX_TIMER;

   /* Point to the TIMER peripheral register. */
   notifier.nrfx_timer.timer.p_reg =
       (NRF_TIMER_Type *)DT_REG_ADDR(DT_NODELABEL(timer20));

   /* Event address that signals one operation is complete (e.g. SPIM END). */
   notifier.nrfx_timer.end_seq_event = nrfx_spim_end_event_address_get(&spim);

   /* Set to the number of identical operations per period if more than one. */
   notifier.nrfx_timer.extra_main_ops = 0;

Step 2 — Initialize the Sequencer
===================================

Populate a ``ppi_seq_config`` structure and call ``ppi_seq_init()``.
All peripheral registers that will be triggered by the sequencer must be fully configured before calling ``ppi_seq_init()``.

Single task per period (default GRTC timing source):

.. code-block:: c

   static struct ppi_seq_notifier notifier; /* configured above */
   static struct ppi_seq seq;

   static const struct ppi_seq_config config = {
       .notifier  = &notifier,
       .task      = TASK_ADDR,        /* address of the task register to trigger */
       .callback  = ppi_seq_callback,
       /* To override the timing source, set one of:
        * .rtc_reg   = NRF_RTC1
        * .timer_reg = NRF_TIMER2    */
   };

   int ret = ppi_seq_init(&seq, &config);

Multiple tasks per period (RTC or GRTC+TIMER):

Each extra task is specified as a ``{task_address, offset_µs}`` pair.
The maximum number of extra tasks is limited by the available compare channels: TIMER provides (compare channels − 1) extra tasks, and RTC provides (compare channels − 2).

.. code-block:: c

   static struct ppi_seq_notifier notifier; /* configured above */
   static struct ppi_seq seq;

   static const struct ppi_seq_extra_op ops[] = {
       { .task = TASK_ADDR1, .offset = 20 }, /* triggered 20 µs after period start */
       { .task = TASK_ADDR2, .offset = 40 }, /* triggered 40 µs after period start */
   };

   static const struct ppi_seq_config config = {
       .notifier        = &notifier,
       .task            = TASK_ADDR0,          /* first task at period start */
       .callback        = ppi_seq_callback,
       .extra_ops       = ops,
       .extra_ops_count = ARRAY_SIZE(ops),
       .timer_reg       = NRF_TIMER2,          /* required for GRTC+TIMER mode */
       /* .rtc_reg = NRF_RTC1               */ /* alternative: RTC timing */
   };

   int ret = ppi_seq_init(&seq, &config);

Step 3 — Start and Stop
========================

.. code-block:: c

   /* ppi_seq_start(seq, period_us, batch_cnt, repeat_cnt)
    *   period_us  — interval between task triggers, in microseconds
    *   batch_cnt  — number of periods per batch; callback fires once per batch
    *   repeat_cnt — number of batches before auto-stop; UINT32_MAX = run forever
    */
   ret = ppi_seq_start(&seq, 1000 /* 1 ms */, 32 /* batch of 32 */, UINT32_MAX);

   /* Stop at any time. Safe to call from any context. */
   ppi_seq_stop(&seq);

The user callback signature is:

.. code-block:: c

   void ppi_seq_callback(struct ppi_seq *seq, bool last);
   /* seq  — sequencer instance that completed the batch
    * last — true if this is the final batch before the sequencer stops */

Use Cases by Mode
*****************

SPIM — Periodic SPI Sensor Reads
==================================

An accelerometer is polled at 1 kHz.
Samples are collected in batches of 32 before the CPU is woken to process them.
SPI transfers are 6 bytes (read register + 5 data bytes).

Use the ``ppi_seq_i2c_spi`` helper and configure the devicetree node with ``"nordic,ppi-seq-spi"``.

.. code-block:: dts

   &spi130 {
       compatible = "nordic,ppi-seq-spi";
       status = "okay";
       pinctrl-0 = <&spi130_default_alt>;
       pinctrl-1 = <&spi130_sleep_alt>;
       pinctrl-names = "default", "sleep";
       overrun-character = <0x00>;
       memory-regions = <&cpuapp_dma_region>;
       cs-gpios = <&gpio0 8 GPIO_ACTIVE_LOW>;
       frequency = <8000000>;
       rtc = <&rtc130>; /* lowest power at 1 ms period */
   };

.. code-block:: c

   #define PERIOD_US    1000  /* 1 ms */
   #define TRANSFER_LEN 6
   #define BATCH_LEN    32

   static void batch_done(const struct device *dev,
                          struct ppi_seq_i2c_spi_batch *batch,
                          bool last, void *user_data)
   {
       /* batch->rx_buf contains 32 × 6 = 192 bytes of sensor data. */
       process_samples(batch->rx_buf, BATCH_LEN);
   }

   static int start_accel_sampling(const struct device *spi_dev)
   {
       static uint8_t tx_buf[TRANSFER_LEN];
       static uint8_t rx_buf[2][TRANSFER_LEN * BATCH_LEN];

       /* Prepare the SPI read command sent identically for every transfer. */
       tx_buf[0] = ACCEL_READ_CMD | ACCEL_ADDR;

       struct ppi_seq_i2c_spi_job job = {
           .desc.spim = {
               .p_tx_buffer = tx_buf,
               .tx_length   = TRANSFER_LEN,
               .p_rx_buffer = rx_buf[0],
               .rx_length   = TRANSFER_LEN,
           },
           .rx_second_buf = rx_buf[1],
           .repeat        = UINT32_MAX,  /* run indefinitely */
           .batch_cnt     = BATCH_LEN,
           .tx_postinc    = false,       /* same TX command for every transfer */
           .cb            = batch_done,
       };

       return ppi_seq_i2c_spi_start(spi_dev, PERIOD_US, &job);
   }

.. note::

   With RTC timing and a 1 ms period, expect approximately 70% reduction in current consumption compared to interrupt-driven polling.

TWIM — Periodic I2C Sensor Reads
==================================

A temperature/humidity sensor is read over I2C every 50 ms.
Batches of 10 readings are accumulated before notifying the application.

.. code-block:: dts

   &i2c130 {
       compatible = "nordic,ppi-seq-i2c";
       status = "okay";
       pinctrl-0 = <&i2c130_default_alt>;
       pinctrl-1 = <&i2c130_sleep_alt>;
       pinctrl-names = "default", "sleep";
       clock-frequency = <I2C_BITRATE_STANDARD>;
       rtc = <&rtc130>;
   };

.. code-block:: c

   #define PERIOD_US    50000  /* 50 ms */
   #define TRANSFER_LEN 4      /* address byte + 3 data bytes */
   #define BATCH_LEN    10

   static void batch_done(const struct device *dev,
                          struct ppi_seq_i2c_spi_batch *batch,
                          bool last, void *user_data)
   {
       process_temperature_batch(batch->rx_buf, BATCH_LEN);
   }

   static int start_temp_sampling(const struct device *i2c_dev)
   {
       static uint8_t tx_buf[TRANSFER_LEN];
       static uint8_t rx_buf[2][TRANSFER_LEN * BATCH_LEN];

       tx_buf[0] = SENSOR_I2C_ADDR << 1; /* write address */
       tx_buf[1] = TEMP_REG;

       struct ppi_seq_i2c_spi_job job = {
           .desc.twim = {
               .p_tx_buffer = tx_buf,
               .tx_length   = 2,
               .p_rx_buffer = rx_buf[0],
               .rx_length   = TRANSFER_LEN - 2,
           },
           .rx_second_buf = rx_buf[1],
           .repeat        = UINT32_MAX,
           .batch_cnt     = BATCH_LEN,
           .tx_postinc    = false,
           .cb            = batch_done,
       };

       return ppi_seq_i2c_spi_start(i2c_dev, PERIOD_US, &job);
   }

GRTC — Single Task, Low Power
===============================

The GRTC interval channel is the default timing source, used when neither ``rtc`` nor ``timer`` is specified in the configuration.
GRTC provides a good balance of precision and power for a single ``ppi_seq`` instance.
On nRF54 Series devices, only one sequencer can use the GRTC interval channel at a time.

Choose GRTC when:

* The target is an nRF54 Series device where no RTC peripheral is available.
* Only a single sequencer instance is needed.
* The period is in the range of a few milliseconds or longer.
* Better precision than RTC is needed (GRTC uses a 1 MHz reference).

Because the GRTC interval channel is the default, no register override is needed in the ``ppi_seq_config``:

.. code-block:: c

   static struct ppi_seq_notifier notifier;
   static struct ppi_seq seq;

   /* System timer notifier: GRTC and k_timer share the low-frequency clock. */
   notifier.type   = PPI_SEQ_NOTIFIER_SYS_TIMER;
   notifier.offset = 0;

   static const struct ppi_seq_config config = {
       .notifier  = &notifier,
       .task      = nrfx_spim_start_task_address_get(&spim),
       .callback  = my_callback,
       /* No .rtc_reg or .timer_reg — GRTC interval channel is used automatically. */
   };

   ppi_seq_init(&seq, &config);
   ppi_seq_start(&seq, 5000 /* 5 ms */, 20 /* 20 per batch */, UINT32_MAX);

.. note::

   GRTC requires occasional high-frequency clock activity to synchronise its 1 MHz and 32 kHz clock domains, making it slightly less power-efficient than RTC.
   Expect approximately 50% power reduction for periods under 5 ms and approximately 25% up to 25 ms.

RTC — Lowest Power, Multiple Tasks per Period
==============================================

An IMU requires a write transfer followed by a read transfer every 2 ms, separated by 50 µs.
RTC is selected for the lowest possible power draw.

RTC timing supports multiple tasks per period using its compare channels.
The maximum number of extra tasks is (RTC compare channels − 2).

**Devicetree (via** ``ppi_seq_i2c_spi``\ **):**

.. code-block:: dts

   &spi130 {
       compatible = "nordic,ppi-seq-spi";
       /* ... */
       rtc = <&rtc130>;
       extra_transfers = <50>; /* one extra transfer at +50 µs */
   };

**Low-level** ``ppi_seq`` **setup:**

.. code-block:: c

   static struct ppi_seq_notifier notifier;
   static struct ppi_seq seq;

   notifier.type   = PPI_SEQ_NOTIFIER_SYS_TIMER;
   notifier.offset = 50; /* last operation takes approximately 50 µs */

   static const struct ppi_seq_extra_op ops[] = {
       { .task = nrfx_spim_start_task_address_get(&spim_read), .offset = 50 },
   };

   static const struct ppi_seq_config config = {
       .notifier        = &notifier,
       .task            = nrfx_spim_start_task_address_get(&spim_write),
       .callback        = my_callback,
       .extra_ops       = ops,
       .extra_ops_count = ARRAY_SIZE(ops),
       .rtc_reg         = NRF_RTC1,
   };

   ppi_seq_init(&seq, &config);
   ppi_seq_start(&seq, 2000 /* 2 ms */, 50 /* batch of 50 */, UINT32_MAX);

.. note::

   RTC provides the lowest power consumption because it runs entirely from the 32 kHz low-frequency clock with no high-frequency synchronisation overhead.
   Expect approximately 70% power reduction for periods under 5 ms and approximately 50% around 25 ms.

.. note::

   RTC period resolution is one 32 kHz tick (~30.5 µs).
   Periods shorter than approximately 100 µs are not suitable for RTC timing.

TIMER — High Precision, Single Task
=====================================

A high-speed ADC is triggered every 100 µs via SPI.
Precise timing is the primary requirement; power savings are a secondary concern.
Batches of 100 readings are processed together.

TIMER provides the finest timing precision but keeps the peripheral clocked continuously, significantly increasing idle current.
It is recommended only when sub-tick GRTC/RTC precision is insufficient and the application already operates in a performance-oriented power mode.

.. warning::

   TIMER does not support multiple tasks per period.
   Use RTC or GRTC+TIMER mode when multiple tasks per period are required.

.. warning::

   Do not combine TIMER as a timing source with the ``k_timer`` (system timer) notifier, because they are clocked from different sources.
   Use the TIMER counter notifier instead.

**Devicetree (via** ``ppi_seq_i2c_spi``\ **):**

.. code-block:: dts

   &spi130 {
       compatible = "nordic,ppi-seq-spi";
       /* ... */
       timer          = <&timer20>; /* period timing source */
       timer_notifier = <&timer21>; /* batch completion counter */
   };

**Low-level** ``ppi_seq`` **setup:**

.. code-block:: c

   static struct ppi_seq_notifier notifier;
   static struct ppi_seq seq;

   /* TIMER notifier: fires immediately when the batch completes. */
   IRQ_CONNECT(DT_IRQN(DT_NODELABEL(timer21)),
               DT_IRQ_BY_IDX(DT_NODELABEL(timer21), 0, priority),
               nrfx_timer_irq_handler, &notifier.nrfx_timer.timer, 0);

   notifier.type = PPI_SEQ_NOTIFIER_NRFX_TIMER;
   notifier.nrfx_timer.timer.p_reg =
       (NRF_TIMER_Type *)DT_REG_ADDR(DT_NODELABEL(timer21));
   notifier.nrfx_timer.end_seq_event =
       nrfx_spim_end_event_address_get(&spim);
   notifier.nrfx_timer.extra_main_ops = 0;

   static const struct ppi_seq_config config = {
       .notifier  = &notifier,
       .task      = nrfx_spim_start_task_address_get(&spim),
       .callback  = my_callback,
       .timer_reg = NRF_TIMER2, /* TIMER as the period timing source */
   };

   ppi_seq_init(&seq, &config);
   ppi_seq_start(&seq, 100 /* 100 µs */, 100 /* batch of 100 */, UINT32_MAX);

Timing Source Selection Guide
*******************************

.. list-table::
   :header-rows: 1
   :widths: 20 15 20 10 35

   * - Timing Source
     - Period Precision
     - Multiple Tasks/Period
     - Power
     - Recommended For
   * - **GRTC** (default)
     - ~1 µs
     - No
     - Medium
     - General use on nRF54; single instance only.
   * - **GRTC + TIMER**
     - ~1 µs
     - Yes
     - Medium-High
     - Multiple tasks per period on nRF54.
   * - **RTC**
     - ~30.5 µs (32 kHz tick)
     - Yes
     - Lowest
     - Battery-powered devices; periods ≥ ~100 µs.
   * - **TIMER**
     - Sub-µs
     - No
     - High
     - High-speed peripherals; CPU-load reduction only.

Notifier Selection Guide
*************************

.. list-table::
   :header-rows: 1
   :widths: 20 15 15 50

   * - Notifier
     - Precision
     - Extra Power
     - Recommended For
   * - ``k_timer`` (system timer)
     - Low (adds ¼-period margin)
     - None
     - Periods ≥ ~1 ms; low-power applications.
   * - TIMER counter
     - High (fires immediately)
     - +5–10 µA
     - Periods < ~500 µs; use with TIMER timing source.

Compatibility rules:

* ``k_timer`` + GRTC — compatible (both use the low-frequency clock).
* ``k_timer`` + RTC — compatible.
* ``k_timer`` + TIMER — **not recommended** (different clock sources).
* TIMER counter + TIMER — recommended pairing.
* TIMER counter + GRTC — compatible.

Limitations and Pitfalls
*************************

Time-critical processing
=========================

While the sequencer is running, each period fires unconditionally at hardware speed.
If your callback or batch-processing code takes longer than one period, the hardware will not wait and the next transfer fires regardless.
This can cause buffer overwrite or undefined behaviour.
Avoid long blocking operations such as flash writes while the sequencer is active.

System timer precision
=======================

The ``k_timer`` notifier estimates the batch completion time by adding a quarter-period safety margin.
For very short periods this margin may be larger than the period itself, making the notifier unreliable.
Use the TIMER counter notifier for periods shorter than approximately 500 µs.

GRTC instance limit
====================

On nRF54 Series devices, only one TIMER channel supports the GRTC interval feature.
Only one ``ppi_seq`` instance can use the default GRTC timing source at a time.
If two simultaneous sequencers are needed, assign one to an RTC or TIMER source.

RTC precision floor
====================

The RTC ticks at 32 kHz, giving a period resolution of approximately 30.5 µs per tick.
Period values are rounded to the nearest tick.
RTC is not suitable for periods shorter than approximately 100 µs or for applications requiring sub-tick precision.

TIMER power cost
=================

A TIMER kept running as a timing source or batch counter continuously draws current.
At short periods the additional 5–10 µA for the counter is negligible, but using TIMER as the main timing source for long idle periods wastes significant energy compared to RTC or GRTC.

Buffer sizing
==============

When using ``ppi_seq_i2c_spi``, each RX buffer must be large enough to hold an entire batch: ``rx_length = transfer_length × batch_cnt``.
With ``tx_postinc = true``, both TX buffers must be pre-filled to full batch size before calling ``ppi_seq_i2c_spi_start()``.

Static storage requirement
===========================

The ``ppi_seq_notifier`` and ``ppi_seq_config`` structures must have ``static`` storage duration.
Placing them on the stack and returning from the initialisation function results in dangling pointer reads at runtime.
