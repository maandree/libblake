CPPFLAGS_BLAKE384 = -DSUPPORT_BLAKE384

OBJ_BLAKE384 =\
	libblake_blake384_digest.o\
	libblake_blake384_init.o\
	libblake_blake384_init2.o\
	libblake_blake384_update.o

OBJ_BLAKEB =\
	libblake_blake384_digest_get_required_input_size.o\
	libblake_internal_blakeb_digest.o\
	libblake_internal_blakeb_update.o
