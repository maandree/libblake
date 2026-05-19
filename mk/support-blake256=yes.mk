CPPFLAGS_BLAKE256 = -DSUPPORT_BLAKE256

OBJ_BLAKE256 =\
	libblake_blake256_digest.o\
	libblake_blake256_digest_get_required_input_size.o\
	libblake_blake256_init.o\
	libblake_blake256_init2.o\
	libblake_blake256_update.o

OBJ_BLAKES =\
	libblake_blake224_digest_get_required_input_size.o\
	libblake_internal_blakes_digest.o\
	libblake_internal_blakes_update.o
