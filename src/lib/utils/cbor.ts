import { Encoder, Options } from "cbor-x";

const encoderDefaults: Options = {
  tagUint8Array: false,
  useRecords: false,
  mapsAsObjects: false,
  // @ts-ignore
  useTag259ForMaps: false,
};

export const cborDecode = (
  input: Buffer | Uint8Array,
  options: Options = encoderDefaults,
): any => {
  const params = { ...encoderDefaults, ...options };
  const enc = new Encoder(params);
  return enc.decode(input);
};

export const cborEncode = (
  obj: unknown,
  options: Options = encoderDefaults,
): Buffer => {
  const params = { ...encoderDefaults, ...options };
  const enc = new Encoder(params);
  return enc.encode(obj);
};
