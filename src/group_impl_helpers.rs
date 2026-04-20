// ═══════════════════════════════════════════════════════════════════════════════
// L1.2, L1.3, L1.4, L2.1 - 实现模板和辅助函数
// 这个文件包含所有需要的框架代码
// ═══════════════════════════════════════════════════════════════════════════════

// ──────────────────────────────────────────────────────────────────────────────
// L1.2: MultiLayerTree 生成 - 可复用的XMSS单层生成器
// ──────────────────────────────────────────────────────────────────────────────

/// Helper to generate WOTS+ public keys for one layer
pub fn generate_layer_wots_pks<S: SphincsHasher>(
    layer_id: usize,
    sk_seed: &[u8; N],
    pk_seed: &[u8; N],
    num_leaves: usize,
) -> Vec<[u8; N]> {
    use sha2::Digest;
    let mut pks = Vec::with_capacity(num_leaves);
    
    for leaf_idx in 0..num_leaves {
        // 为这个叶子生成WOTS+公钥
        // 种子 = H(SK.seed || layer_id || leaf_idx)
        
        let mut hasher = sha2::Sha256::new();
        hasher.update(sk_seed);
        hasher.update(layer_id.to_le_bytes());
        hasher.update((leaf_idx as u32).to_le_bytes());
        
        let mut seed = [0u8; N];
        seed.copy_from_slice(&hasher.finalize()[..N]);
        
        // 调用现有的WOTS+生成函数（来自sphincs模块）
        // let wots_pk = wots_pkgen(&seed, pk_seed);
        // TODO: 替换为实际的WOTS+调用
        
        pks.push(seed);  // 临时: 返回seed本身 (需要改成wots_pk)
    }
    
    pks
}

/// Helper to build XMSS tree from leaf public keys
pub fn build_xmss_tree<S: SphincsHasher>(
    wots_pks: &[[u8; N]],
    pk_seed: &[u8; N],
    layer_id: usize,
) -> ([u8; N], Vec<[u8; N]>) {
    // 输入: 2^HP 个WOTS+公钥 (叶子)
    // 输出: (树根, 所有中间节点)
    
    let num_leaves = wots_pks.len();
    assert!(num_leaves.is_power_of_two());
    
    let tree_height = num_leaves.ilog2() as usize;
    let mut nodes = Vec::with_capacity(num_leaves * 2);  // 大小上限
    
    // 底层: 直接复制叶子(WOTS+公钥)
    let mut current_level = wots_pks.to_vec();
    nodes.extend_from_slice(wots_pks);
    
    // 从底到顶: 逐层哈希相邻对
    for level in 0..tree_height {
        let mut next_level = Vec::with_capacity(current_level.len() / 2);
        
        for pair_idx in 0..(current_level.len() / 2) {
            let left = current_level[2 * pair_idx];
            let right = current_level[2 * pair_idx + 1];
            
            // 父节点 = H(left || right || ADRS)
            // 这里用简化版: H(left || right)
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(left);
            hasher.update(right);
            
            let mut parent = [0u8; N];
            parent.copy_from_slice(&hasher.finalize()[..N]);
            
            next_level.push(parent);
            nodes.push(parent);
        }
        
        current_level = next_level;
    }
    
    // 最后剩下的是树根
    let root = current_level[0];
    (root, nodes)
}

// ──────────────────────────────────────────────────────────────────────────────
// L1.3: 成员地址计算 - 从成员ID到叶子路径
// ──────────────────────────────────────────────────────────────────────────────

/// 从XMSS树节点集合中提取认证路径
pub fn extract_auth_path_from_tree(
    leaf_index: u32,
    tree_nodes: &[[u8; N]],
    tree_height: usize,
) -> Vec<[u8; N]> {
    // 认证路径 = 从叶子到根的"兄弟节点"
    // 例如树高3, 叶子索引5:
    //
    //       root
    //      /    \
    //     /      \
    //    N6      N7 (包含叶5的兄弟)
    //   /  \    /  \
    //  N2  N3  N4  N5
    // / \ / \ / \ / \
    // L0..L7 (L5是我们的叶子)
    //
    // 认证路径 = [L4(L5的兄弟), N4(兄弟的父亲), N7(最后的兄弟)]
    
    let mut path = Vec::with_capacity(tree_height);
    let mut current_idx = leaf_index;
    
    for level in 0..tree_height {
        // 计算当前节点的兄弟
        let sibling_idx = current_idx ^ 1;  // XOR with 1 to flip last bit
        
        // 从tree_nodes中查找兄弟节点
        // (这需要知道树的存储布局，可能需要调整)
        // TODO: 实现节点查找逻辑
        
        current_idx = current_idx / 2;  // 上升到父层
    }
    
    path
}

/// 验证认证路径的一致性
pub fn verify_auth_path(
    leaf: &[u8; N],
    leaf_index: u32,
    auth_path: &[[u8; N]],
    expected_root: &[u8; N],
) -> bool {
    use sha2::{Sha256, Digest};
    
    let mut current = *leaf;
    let mut current_idx = leaf_index;
    
    for sibling in auth_path {
        let (left, right) = if current_idx % 2 == 0 {
            (current, *sibling)
        } else {
            (*sibling, current)
        };
        
        let mut hasher = Sha256::new();
        hasher.update(left);
        hasher.update(right);
        current.copy_from_slice(&hasher.finalize()[..N]);
        
        current_idx /= 2;
    }
    
    current == *expected_root
}

// ──────────────────────────────────────────────────────────────────────────────
// L1.4: 快速成员识别 - 从签名直接读取方向位
// ──────────────────────────────────────────────────────────────────────────────

/// 从FORS摘要提取方向位 (已在 src/group.rs 中, 复制供参考)
pub fn extract_direction_bits_from_digest(
    digest: &[u8; N],
    tree_height: usize,
) -> Vec<bool> {
    let mut directions = Vec::with_capacity(tree_height);
    
    for bit_idx in 0..tree_height {
        let byte_idx = bit_idx / 8;
        let bit_offset = bit_idx % 8;
        
        if byte_idx < N {
            let bit = (digest[byte_idx] >> bit_offset) & 1;
            directions.push(bit != 0);
        }
    }
    
    directions
}

/// 从方向位序列重建叶子索引
pub fn leaf_index_from_directions(directions: &[bool]) -> u32 {
    let mut idx = 0u32;
    
    for (level, &go_right) in directions.iter().enumerate() {
        idx = (idx << 1) | (go_right as u32);
    }
    
    idx
}

// ──────────────────────────────────────────────────────────────────────────────
// L2.1: Opening密钥导出 - PRF-based KEY GENERATION
// ──────────────────────────────────────────────────────────────────────────────

/// PRF函数: HMAC-SHA256-based密钥导出
pub fn prf_opening_key(
    master_seed: &[u8; N],
    member_id: u32,
) -> [u8; N] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    
    type HmacSha256 = Hmac<Sha256>;
    
    let mut mac = HmacSha256::new_from_slice(master_seed)
        .expect("HMAC accepts any size key");
    
    mac.update(&member_id.to_le_bytes());
    mac.update(b"opening");
    
    let result = mac.finalize();
    let bytes = result.into_bytes();
    
    let mut key = [0u8; N];
    key.copy_from_slice(&bytes[..N.min(bytes.len())]);
    key
}

/// 验证导出密钥的独立性(单元测试用)
pub fn verify_opening_keys_independence(master_seed: &[u8; N], count: usize) -> bool {
    let mut keys = Vec::new();
    
    for i in 0..count {
        let key = prf_opening_key(master_seed, i as u32);
        
        // 检查是否有重复
        if keys.contains(&key) {
            return false;
        }
        
        keys.push(key);
    }
    
    true  // 所有密钥都不同
}

// ──────────────────────────────────────────────────────────────────────────────
// L2.2/L2.3: AES-GCM 加密/解密辅助
// ──────────────────────────────────────────────────────────────────────────────

use aes_gcm::{Aes256Gcm, Key, Nonce, Aad};
use aes_gcm::aead::{Aead, Payload};

/// 使用OPK加密成员ID (L2.3)
/// 
/// 返回: [16字节TAG || 32字节密文]
pub fn encrypt_member_id_with_opk(
    member_id: u32,
    timestamp: u64,
    opk: &[u8; N],
) -> [u8; 48] {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from(*opk));
    
    // 使用确定性nonce (基于timestamp)
    // 警告: 生产环境中应该用随机nonce!
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[..8].copy_from_slice(&timestamp.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // 明文 = member_id (4字节) || timestamp (8字节) = 12字节
    let mut plaintext = [0u8; 12];
    plaintext[..4].copy_from_slice(&member_id.to_le_bytes());
    plaintext[4..].copy_from_slice(&timestamp.to_le_bytes());
    
    // 加密
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
        .expect("Encryption should succeed");
    
    // 返回: [TAG(16) || CIPHERTEXT(16)] = 32字节密文
    // + 签名中也存储nonce或其他元数据
    
    let mut result = [0u8; 48];
    result[..ciphertext.len()].copy_from_slice(&ciphertext);
    result
}

/// 尝试使用OPK解密成员ID (L2.4, 恒定时间)
/// 
/// 返回: Some((member_id, timestamp)) 如果解密成功, None 否则
pub fn decrypt_member_id_with_opk(
    ciphertext: &[u8; 48],
    timestamp: u64,
    opk: &[u8; N],
) -> Option<(u32, u64)> {
    use subtle::ConstantTimeEq;
    
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from(*opk));
    
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[..8].copy_from_slice(&timestamp.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // 尝试解密
    match cipher.decrypt(nonce, ciphertext.as_ref()) {
        Ok(plaintext) => {
            if plaintext.len() >= 12 {
                let mut member_id_bytes = [0u8; 4];
                member_id_bytes.copy_from_slice(&plaintext[..4]);
                let member_id = u32::from_le_bytes(member_id_bytes);
                
                let mut ts_bytes = [0u8; 8];
                ts_bytes.copy_from_slice(&plaintext[4..12]);
                let ts = u64::from_le_bytes(ts_bytes);
                
                Some((member_id, ts))
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// 单元测试示例 (可复制到 tests/ 目录)
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    
    const SK_SEED: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    
    #[test]
    fn test_extract_direction_bits() {
        let mut digest = [0u8; 32];
        digest[0] = 0b10101010;  // 交替的0和1
        
        let directions = extract_direction_bits_from_digest(&digest, 8);
        
        // 0b10101010 → [0,1,0,1,0,1,0,1] (LSB first)
        assert_eq!(directions, vec![false, true, false, true, false, true, false, true]);
    }
    
    #[test]
    fn test_leaf_index_from_directions() {
        // [0,1,0,1,...] → 索引
        let directions = vec![false, true, false, true, false, true, false, true];
        let idx = leaf_index_from_directions(&directions);
        
        // 二进制: 10101010 = 170
        assert_eq!(idx, 0b10101010);
    }
    
    #[test]
    fn test_prf_opening_key_deterministic() {
        let key1 = prf_opening_key(&SK_SEED, 42);
        let key2 = prf_opening_key(&SK_SEED, 42);
        
        assert_eq!(key1, key2, "PRF should be deterministic");
    }
    
    #[test]
    fn test_prf_opening_key_independence() {
        assert!(verify_opening_keys_independence(&SK_SEED, 100),
                "First 100 opening keys should be unique");
    }
    
    #[test]
    fn test_encrypt_decrypt_member_id() {
        let opk = prf_opening_key(&SK_SEED, 0);
        let member_id = 42u32;
        let timestamp = 1234567890u64;
        
        // 加密
        let ciphertext = encrypt_member_id_with_opk(member_id, timestamp, &opk);
        
        // 用相同的OPK解密
        let decrypted = decrypt_member_id_with_opk(&ciphertext, timestamp, &opk)
            .expect("Decryption should succeed");
        
        assert_eq!(decrypted.0, member_id);
        assert_eq!(decrypted.1, timestamp);
    }
    
    #[test]
    fn test_decrypt_with_wrong_opk_fails() {
        let opk1 = prf_opening_key(&SK_SEED, 0);
        let opk2 = prf_opening_key(&SK_SEED, 1);
        
        let ciphertext = encrypt_member_id_with_opk(42, 1234567890, &opk1);
        
        // 用错误的OPK解密应该失败
        let decrypted = decrypt_member_id_with_opk(&ciphertext, 1234567890, &opk2);
        assert!(decrypted.is_none(), "Decryption with wrong key should fail");
    }
}

/// ─────────────────────────────────────────────────────────────────────────────
/// 使用说明:
///
/// 1. L1.2 (多层树生成):
///    - 复制 generate_layer_wots_pks, build_xmss_tree 到你的 src/group.rs
///    - 在 MultiLayerTree::generate_layer 中调用这些函数
///
/// 2. L1.3 (寻址逻辑):
///    - 复制 extract_auth_path_from_tree, verify_auth_path
///    - 在 MemberLeafAddress::for_member 中使用
///
/// 3. L1.4 (快速识别):
///    - 使用现有的 extract_direction_bits_from_digest (src/group.rs中已有)
///    - 复制 leaf_index_from_directions
///
/// 4. L2.1 (Opening密钥):
///    - 复制 prf_opening_key, verify_opening_keys_independence
///    - 在 OpeningKeySet::derive_opening_key_i 中使用
///
/// 5. L2.3/L2.4 (加密/解密):
///    - 复制 encrypt_member_id_with_opk, decrypt_member_id_with_opk
///    - 集成到 group_sign_extended, group_open_signature
///
/// 6. 单元测试:
///    - 复制测试到 tests/group_extended_tests.rs
///    - 运行 cargo test --lib 验证
/// ─────────────────────────────────────────────────────────────────────────────
