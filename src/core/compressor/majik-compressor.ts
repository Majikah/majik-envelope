import {
  init,
  compress as zstdCompress,
  decompress as zstdDecompress,
} from "@bokuweb/zstd-wasm";
import { gzipSync, gunzipSync } from "fflate";

type SupportedInput = string | object | ArrayBuffer | Uint8Array;
export type MajikCompressorType = "str" | "json" | "blob";
export type CompressionMode = "binary" | "plaintext";

export class MajikCompressor {
  private static PREFIX = "mjkcmp";
  private static initialized = false;

  private static async ensureInit() {
    if (!this.initialized) {
      await init(); // only init Zstd for binary mode
      this.initialized = true;
    }
  }

  private static encodeInput(input: SupportedInput): {
    type: MajikCompressorType;
    data: Uint8Array;
  } {
    if (typeof input === "string")
      return { type: "str", data: new TextEncoder().encode(input) };
    if (input instanceof Uint8Array) return { type: "blob", data: input };
    if (input instanceof ArrayBuffer)
      return { type: "blob", data: new Uint8Array(input) };
    if (typeof input === "object")
      return {
        type: "json",
        data: new TextEncoder().encode(JSON.stringify(input)),
      };
    throw new Error("Unsupported input type for MajikCompressor");
  }

  private static decodeOutput(
    type: MajikCompressorType,
    data: Uint8Array,
  ): string | Record<string, any> | Uint8Array {
    if (type === "str") return new TextDecoder().decode(data);
    if (type === "json") return JSON.parse(new TextDecoder().decode(data));
    if (type === "blob") return data;
    throw new Error(`Unsupported type for decoding: ${type}`);
  }

  // --- Compress input and return string ---
  public static async compress(
    mode: CompressionMode,
    input: SupportedInput,
    level: number = 9,
  ): Promise<string> {
    const { type, data } = this.encodeInput(input);

    let compressed: Uint8Array;

    if (mode === "binary") {
      await this.ensureInit();
      compressed = zstdCompress(data, level);
    } else {
      // plaintext mode → fflate gzip
      compressed = gzipSync(data);
    }

    const b64 = this.uint8ArrayToBase64(compressed);
    return `${this.PREFIX}:${type}:${b64}`;
  }

  // --- Decompress string with prefix ---
  public static async decompress(
    mode: CompressionMode,
    compressedStr: string,
  ): Promise<string | Record<string, any> | Uint8Array> {
    if (!compressedStr.startsWith(`${this.PREFIX}:`))
      throw new Error("Invalid MajikCompressor string format");

    const [, type, b64] = compressedStr.split(":", 3);
    const compressedData = this.base64ToUint8Array(b64);

    let decompressed: Uint8Array;

    if (mode === "binary") {
      await this.ensureInit();
      decompressed = zstdDecompress(compressedData);
    } else {
      decompressed = gunzipSync(compressedData);
    }

    return this.decodeOutput(type as MajikCompressorType, decompressed);
  }

  public static async decompressJSON(
    compressedStr: string,
  ): Promise<Record<string, any>> {
    const result = await this.decompress("binary", compressedStr);
    if (typeof result === "object" && !(result instanceof Uint8Array))
      return result as Record<string, any>;
    throw new Error("Decompressed data is not JSON");
  }

  public static async decompressString(compressedStr: string): Promise<string> {
    const result = await this.decompress("binary", compressedStr);
    if (typeof result === "string") return result;
    throw new Error("Decompressed data is not a string");
  }

  public static async decompressBlob(
    compressedStr: string,
  ): Promise<Uint8Array> {
    const result = await this.decompress("binary", compressedStr);
    if (result instanceof Uint8Array) return result;
    throw new Error("Decompressed data is not a blob");
  }

  private static uint8ArrayToBase64(u8: Uint8Array): string {
    let binary = "";
    const chunkSize = 0x8000;
    for (let i = 0; i < u8.length; i += chunkSize) {
      const chunk = u8.subarray(i, i + chunkSize);
      binary += String.fromCharCode(...chunk);
    }
    return btoa(binary);
  }

  private static base64ToUint8Array(b64: string): Uint8Array {
    const binary = atob(b64);
    const u8 = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) u8[i] = binary.charCodeAt(i);
    return u8;
  }
}
