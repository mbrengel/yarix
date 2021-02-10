#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

struct PLFile
{
    FILE *f;
    uint8_t exists;
    uint64_t ploffsets[256];
    uint64_t currplprocessed;
    uint32_t currfileid;
    uint64_t currplsz;
};

void plfile_init(struct PLFile *plf, char *path)
{
    if (access(path, F_OK) == -1)
    {
        plf->exists = 0;
    }
    else
    {
        plf->f = fopen(path, "r");
        plf->exists = 1;
        fread(plf->ploffsets, 8, 256, plf->f);
    }
}

void plfile_seek_to_pl(struct PLFile *plf, uint8_t d)
{
    plf->currplprocessed = 0;
    if (!plf->exists || plf->ploffsets[d] == 0xFFFFFFFFFFFFFFFFULL)
    {
        plf->currplsz = 0;
        return;
        
    }
    fseek(plf->f, plf->ploffsets[d] + 256 * 8, SEEK_SET);
    fread(&plf->currplsz, 8, 1, plf->f);
}

uint8_t plfile_pl_has_next(struct PLFile *plf)
{
    return plf->currplprocessed < plf->currplsz;
}

uint32_t plfile_pl_get_next(struct PLFile *plf)
{
    if (plf->currplprocessed++ == 0)
    {
        fread(&plf->currfileid, 4, 1, plf->f);
    } else {
        uint32_t delta = 0;
        uint8_t b = 0;
        int k = 0;
        do
        {
            fread(&b, 1, 1, plf->f);
            delta |= ((b & 0x7FU) << (k * 7));
            k++;
        } while (b & 0x80U);
        plf->currfileid += delta;
    }
    return plf->currfileid;
}

void plfile_close(struct PLFile *plf)
{
    if (plf->exists)
    {
        fclose(plf->f);
    }
}
