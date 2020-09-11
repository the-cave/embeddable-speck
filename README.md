# Embeddable Speck

## What is it?

Embeddable Speck is an implementation of NSA's block cipher [Speck](https://nsacyber.github.io/simon-speck/).
The goal of Embeddable Speck is to make the cipher more suitble for [PSK](https://en.wikipedia.org/wiki/Pre-shared_key) scheme adaptation for embedded systems. 

## What's special? and tradeoffs

* The key scheduler is not included, resulting in a lighter-weight implementation
* Asynchronous execution with callback interfaces
* Hightly cooperative polling, non-blocking encryption and decryption
* Optional concurrency with multiple instances
* No CPU hogging
* 128-bit block with 128-bit key mode only
* Static (and precomputed) key schedule matrix must be present
* Commercial usage is highly discouraged, personal usage only

## Why the library is not recommended aside from personal usages?

* The algorithm was designed by NSA.
* PSK nature of the library, with a static key, and without a key-exchange mechanism whatsoever, make the device adopting this library susceptible to key-recovery attacks by reverse engineering.
* At best, the library can be used for your DIY remote-controlled door locker, assuming that you do not use it to lock anything NSA or the US government would care about.
* Safer alternatives available. (Try [Embeddable SPARX](https://github.com/the-cave/embeddable-sparx) instead; different algorithm, same API)

## Porting
No need, the code is hardware and platform agnostic. It will run everywhere as long as C language works. You can even [run the test](#Testing) on your PC.

However, at the very least, 32-bit processor like [Arm Cortex-M0](https://www.arm.com/products/silicon-ip-cpu/cortex-m/cortex-m0) is recommended.

## Usages

See [the test](./test/main.c) for an example.

### Commons

Declare the key schedule matrix
~~~ C
static const uint64_t key_schedule[EMBEDDABLE_SPECK__ROUND] = ...;
~~~

Declare the configuration of an instance including the callback function
~~~ C
static void encrypted_handler(uint8_t *result);
static const EmbeddableSpeck_Config encryption_config = {
    .key_schedule = (uint64_t *)key_schedule,
    .finished = &encrypted_handler,
};
~~~

Declare state in RAM and reset the memory on application start
~~~ C
static EmbeddableSpeck_State encryption_state;
embeddable_speck__init(&encryption_state);
~~~

### Encryption

Start by feeding the input data to an instance
~~~ C
embeddable_speck__start(&encryption_state, plain_text);
~~~

And keep polling for the encryption
~~~ C
embeddable_speck__encryption_poll(&encryption_config, &encryption_state);
~~~

### Decryption

The only difference from the encryption part is the polling function operate on an instance.  
Keeping everything else the same.
~~~ C
embeddable_speck__decryption_poll(&decryption_config, &decryption_state);
~~~

If the explanation is not clear you can always see an actual usage in [the test](./test/main.c).

Both `embeddable_speck__encryption_poll` and `embeddable_speck__decryption_poll` operations are safe to be called periodically.
Just make sure each of them does not operate on the same instance.  
If there is nothing to be done the function would return right away; costing only about a couple of address jump on the hardware running the program.

## Prerequisites

* [GNU Compiler Collection](https://gcc.gnu.org/)
* [GNU Make](https://www.gnu.org/software/make/)

## Testing

Just clone the repository with submodules and `make run`.

## Less controversy one

Please note that non-NSA-designed algorithm is available with the exact same API.
See [Embeddable SPARX](https://github.com/the-cave/embeddable-sparx).

## License

Embeddable Speck is released under the [BSD 3-Clause License](LICENSE.md). :tada:
