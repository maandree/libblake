CPPFLAGS_BLAKE2XS = -DSUPPORT_BLAKE2XS

OBJ_BLAKE2S_2XS =\
	libblake_blake2s_digest.o\
	libblake_blake2s_digest_get_required_input_size.o\
	libblake_blake2s_update.o\
	libblake_blake2s_force_update.o\
	libblake_internal_blake2s_compress.o\
	libblake_internal_blake2s_output_digest.o

OBJ_BLAKE2XS =\
	libblake_blake2xs_digest.o\
	libblake_blake2xs_force_update.o\
	libblake_blake2xs_init.o\
	libblake_blake2xs_predigest.o\
	libblake_blake2xs_predigest_get_required_input_size.o\
	libblake_blake2xs_update.o\
	libblake_internal_blake2xs_init0.o
