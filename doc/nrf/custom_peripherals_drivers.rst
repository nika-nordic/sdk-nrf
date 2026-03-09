.. _custom_peripherals_drivers:

Custom peripherals drivers
##########################

Nordic Semiconductor SoCs contain a variety of hardware peripherals that can be used for many purposes in context of |NCS| applications.
Not all of them maps into existing `Zephyr's device driver API`_, especially when combined together.

Here you can find documentation on how to create your own custom peripheral drivers utilizing `nrfx`_ library and following `Lesson 7 - Device driver model`_.
Premade drivers with samples are also included for reference.

.. toctree::
   :maxdepth: 1
   :caption: Subpages:
   :glob:

   custom_peripherals_drivers/ppi_sequencer
