Only in linux-4.4.13.b/arch/x86/kvm: mmu_audit.c.new
diff -u linux-4.4.13/arch/x86/kvm/mmu.c linux-4.4.13.b/arch/x86/kvm/mmu.c
--- linux-4.4.13/arch/x86/kvm/mmu.c	2016-06-08 03:14:51.000000000 +0200
+++ linux-4.4.13.b/arch/x86/kvm/mmu.c	2016-12-14 18:53:25.015391188 +0100
@@ -1883,14 +1883,32 @@
  * kvm_mmu_get_page(), the only user of for_each_gfn_sp(), has skipped
  * all the obsolete pages.
  */
-#define for_each_gfn_sp(_kvm, _sp, _gfn)				\
+/*#define for_each_gfn_sp(_kvm, _sp, _gfn)				\
 	hlist_for_each_entry(_sp,					\
 	  &(_kvm)->arch.mmu_page_hash[kvm_page_table_hashfn(_gfn)], hash_link) \
-		if ((_sp)->gfn != (_gfn)) {} else
+		if ((_sp)->gfn != (_gfn)) {} else*/
 
-#define for_each_gfn_indirect_valid_sp(_kvm, _sp, _gfn)			\
+#define for_each_gfn_sp_spt(_kvm, _sp, _gfn)                              \
+      hlist_for_each_entry(_sp,                                       \
+        &(_kvm)->arch.mmu_spt_hash[kvm_page_table_hashfn(_gfn)], hash_link) \
+              if ((_sp)->gfn != (_gfn)) {} else
+
+#define for_each_gfn_sp_tdp(_kvm, _sp, _gfn)                              \
+      hlist_for_each_entry(_sp,                                       \
+        &(_kvm)->arch.mmu_tdp_hash[kvm_page_table_hashfn(_gfn)], hash_link) \
+              if ((_sp)->gfn != (_gfn)) {} else
+
+/*#define for_each_gfn_indirect_valid_sp(_kvm, _sp, _gfn)			\
 	for_each_gfn_sp(_kvm, _sp, _gfn)				\
-		if ((_sp)->role.direct || (_sp)->role.invalid) {} else
+		if ((_sp)->role.direct || (_sp)->role.invalid) {} else*/
+
+#define for_each_gfn_indirect_valid_sp_spt(_kvm, _sp, _gfn)             \
+        for_each_gfn_sp_spt(_kvm, _sp, _gfn)                            \
+                if ((_sp)->role.direct || (_sp)->role.invalid) {} else
+
+#define for_each_gfn_indirect_valid_sp_tdp(_kvm, _sp, _gfn)             \
+        for_each_gfn_sp_tdp(_kvm, _sp, _gfn)                            \
+                if ((_sp)->role.direct || (_sp)->role.invalid) {} else
 
 /* @sp->gfn should be write-protected at the call site */
 static int __kvm_sync_page(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp,
@@ -1946,18 +1964,34 @@
 	LIST_HEAD(invalid_list);
 	bool flush = false;
 
-	for_each_gfn_indirect_valid_sp(vcpu->kvm, s, gfn) {
-		if (!s->unsync)
-			continue;
+	if (vcpu->arch.mmu.direct_map) {
+		for_each_gfn_indirect_valid_sp_tdp(vcpu->kvm, s, gfn) {
+			if (!s->unsync)
+				continue;
 
-		WARN_ON(s->role.level != PT_PAGE_TABLE_LEVEL);
-		kvm_unlink_unsync_page(vcpu->kvm, s);
-		if ((s->role.cr4_pae != !!is_pae(vcpu)) ||
-			(vcpu->arch.mmu.sync_page(vcpu, s))) {
-			kvm_mmu_prepare_zap_page(vcpu->kvm, s, &invalid_list);
-			continue;
+			WARN_ON(s->role.level != PT_PAGE_TABLE_LEVEL);
+			kvm_unlink_unsync_page(vcpu->kvm, s);
+			if ((s->role.cr4_pae != !!is_pae(vcpu)) ||
+				(vcpu->arch.mmu.sync_page(vcpu, s))) {
+				kvm_mmu_prepare_zap_page(vcpu->kvm, s, &invalid_list);
+				continue;
+			}
+			flush = true;
 		}
-		flush = true;
+	} else 	{
+                for_each_gfn_indirect_valid_sp_spt(vcpu->kvm, s, gfn) {
+                        if (!s->unsync)
+                                continue;
+
+                        WARN_ON(s->role.level != PT_PAGE_TABLE_LEVEL);
+                        kvm_unlink_unsync_page(vcpu->kvm, s);
+                        if ((s->role.cr4_pae != !!is_pae(vcpu)) ||
+                                (vcpu->arch.mmu.sync_page(vcpu, s))) {
+                                kvm_mmu_prepare_zap_page(vcpu->kvm, s, &invalid_list);
+                                continue;
+                        }
+                        flush = true;
+                }	
 	}
 
 	kvm_mmu_commit_zap_page(vcpu->kvm, &invalid_list);
@@ -2103,38 +2137,73 @@
 		quadrant &= (1 << ((PT32_PT_BITS - PT64_PT_BITS) * level)) - 1;
 		role.quadrant = quadrant;
 	}
-	for_each_gfn_sp(vcpu->kvm, sp, gfn) {
-		if (is_obsolete_sp(vcpu->kvm, sp))
-			continue;
-
-		if (!need_sync && sp->unsync)
-			need_sync = true;
+	
+	if (vcpu->arch.mmu.direct_map) {
+		for_each_gfn_sp_tdp(vcpu->kvm, sp, gfn) {
+			if (is_obsolete_sp(vcpu->kvm, sp))
+				continue;
 
-		if (sp->role.word != role.word)
-			continue;
+			if (!need_sync && sp->unsync)
+				need_sync = true;
 
-		if (sp->unsync && kvm_sync_page_transient(vcpu, sp))
-			break;
+			if (sp->role.word != role.word)
+				continue;
 
-		mmu_page_add_parent_pte(vcpu, sp, parent_pte);
-		if (sp->unsync_children) {
-			kvm_make_request(KVM_REQ_MMU_SYNC, vcpu);
-			kvm_mmu_mark_parents_unsync(sp);
-		} else if (sp->unsync)
-			kvm_mmu_mark_parents_unsync(sp);
+			if (sp->unsync && kvm_sync_page_transient(vcpu, sp))
+				break;
 
-		__clear_sp_write_flooding_count(sp);
-		trace_kvm_mmu_get_page(sp, false);
-		return sp;
+			mmu_page_add_parent_pte(vcpu, sp, parent_pte);
+			if (sp->unsync_children) {
+				kvm_make_request(KVM_REQ_MMU_SYNC, vcpu);
+				kvm_mmu_mark_parents_unsync(sp);
+			} else if (sp->unsync)
+				kvm_mmu_mark_parents_unsync(sp);
+
+			__clear_sp_write_flooding_count(sp);
+			trace_kvm_mmu_get_page(sp, false);
+			return sp;
+		}
+	} else  {
+		for_each_gfn_sp_spt(vcpu->kvm, sp, gfn) {
+        	        if (is_obsolete_sp(vcpu->kvm, sp))
+                	        continue;
+
+	                if (!need_sync && sp->unsync)
+        	                need_sync = true;
+
+                	if (sp->role.word != role.word)
+                        	continue;
+
+	                if (sp->unsync && kvm_sync_page_transient(vcpu, sp))
+        	                break;
+
+                	mmu_page_add_parent_pte(vcpu, sp, parent_pte);
+	                if (sp->unsync_children) {
+        	                kvm_make_request(KVM_REQ_MMU_SYNC, vcpu);
+                	        kvm_mmu_mark_parents_unsync(sp);
+	                } else if (sp->unsync)
+        	                kvm_mmu_mark_parents_unsync(sp);
+
+                	__clear_sp_write_flooding_count(sp);
+	                trace_kvm_mmu_get_page(sp, false);
+        	        return sp;
+        	}
 	}
+
 	++vcpu->kvm->stat.mmu_cache_miss;
 	sp = kvm_mmu_alloc_page(vcpu, parent_pte, direct);
 	if (!sp)
 		return sp;
 	sp->gfn = gfn;
 	sp->role = role;
-	hlist_add_head(&sp->hash_link,
-		&vcpu->kvm->arch.mmu_page_hash[kvm_page_table_hashfn(gfn)]);
+
+	if (vcpu->arch.mmu.direct_map)
+		hlist_add_head(&sp->hash_link,
+	                &vcpu->kvm->arch.mmu_tdp_hash[kvm_page_table_hashfn(gfn)]);
+	else
+		hlist_add_head(&sp->hash_link,
+			&vcpu->kvm->arch.mmu_spt_hash[kvm_page_table_hashfn(gfn)]);
+
 	if (!direct) {
 		if (rmap_write_protect(vcpu, gfn))
 			kvm_flush_remote_tlbs(vcpu->kvm);
@@ -2421,11 +2490,20 @@
 	pgprintk("%s: looking for gfn %llx\n", __func__, gfn);
 	r = 0;
 	spin_lock(&kvm->mmu_lock);
-	for_each_gfn_indirect_valid_sp(kvm, sp, gfn) {
-		pgprintk("%s: gfn %llx role %x\n", __func__, gfn,
-			 sp->role.word);
-		r = 1;
-		kvm_mmu_prepare_zap_page(kvm, sp, &invalid_list);
+	if (kvm->vcpus[0]->arch.mmu.direct_map) {
+		for_each_gfn_indirect_valid_sp_tdp(kvm, sp, gfn) {
+			pgprintk("%s: gfn %llx role %x\n", __func__, gfn,
+				 sp->role.word);
+			r = 1;
+			kvm_mmu_prepare_zap_page(kvm, sp, &invalid_list);
+		}
+	} else 	{
+                for_each_gfn_indirect_valid_sp_spt(kvm, sp, gfn) {
+                        pgprintk("%s: gfn %llx role %x\n", __func__, gfn,
+                                 sp->role.word);
+                        r = 1;  
+                        kvm_mmu_prepare_zap_page(kvm, sp, &invalid_list);
+                }
 	}
 	kvm_mmu_commit_zap_page(kvm, &invalid_list);
 	spin_unlock(&kvm->mmu_lock);
@@ -2447,11 +2525,20 @@
 {
 	struct kvm_mmu_page *s;
 
-	for_each_gfn_indirect_valid_sp(vcpu->kvm, s, gfn) {
-		if (s->unsync)
-			continue;
-		WARN_ON(s->role.level != PT_PAGE_TABLE_LEVEL);
-		__kvm_unsync_page(vcpu, s);
+        if (vcpu->arch.mmu.direct_map) {
+		for_each_gfn_indirect_valid_sp_tdp(vcpu->kvm, s, gfn) {
+			if (s->unsync)
+				continue;
+			WARN_ON(s->role.level != PT_PAGE_TABLE_LEVEL);
+			__kvm_unsync_page(vcpu, s);
+		}
+	} else 	{
+	        for_each_gfn_indirect_valid_sp_spt(vcpu->kvm, s, gfn) {
+        	        if (s->unsync)
+                	        continue;
+	                WARN_ON(s->role.level != PT_PAGE_TABLE_LEVEL);
+        	        __kvm_unsync_page(vcpu, s);
+        	}
 	}
 }
 
@@ -2460,16 +2547,28 @@
 {
 	struct kvm_mmu_page *s;
 	bool need_unsync = false;
+        if (vcpu->arch.mmu.direct_map) {
+		for_each_gfn_indirect_valid_sp_tdp(vcpu->kvm, s, gfn) {
+			if (!can_unsync)
+				return 1;
 
-	for_each_gfn_indirect_valid_sp(vcpu->kvm, s, gfn) {
-		if (!can_unsync)
-			return 1;
-
-		if (s->role.level != PT_PAGE_TABLE_LEVEL)
-			return 1;
+			if (s->role.level != PT_PAGE_TABLE_LEVEL)
+				return 1;
 
-		if (!s->unsync)
-			need_unsync = true;
+			if (!s->unsync)
+				need_unsync = true;
+		}
+	} else	{
+                for_each_gfn_indirect_valid_sp_spt(vcpu->kvm, s, gfn) {
+                        if (!can_unsync)
+                                return 1;
+
+                        if (s->role.level != PT_PAGE_TABLE_LEVEL)
+                                return 1;
+
+                        if (!s->unsync)
+                                need_unsync = true;
+                }
 	}
 	if (need_unsync)
 		kvm_unsync_pages(vcpu, gfn);
@@ -2571,7 +2670,7 @@
 {
 	int was_rmapped = 0;
 	int rmap_count;
-
+//	int r;
 	pgprintk("%s: spte %llx write_fault %d gfn %llx\n", __func__,
 		 *sptep, write_fault, gfn);
 
@@ -2601,12 +2700,13 @@
 	      true, host_writable)) {
 		if (write_fault)
 			*emulate = 1;
+//printk("PMC: pos1 write_fault = %d\n", write_fault);
 		kvm_make_request(KVM_REQ_TLB_FLUSH, vcpu);
 	}
-
 	if (unlikely(is_mmio_spte(*sptep) && emulate))
+//{printk("PMC: spte=%llx\n", *sptep);
 		*emulate = 1;
-
+//}
 	pgprintk("%s: setting spte %llx\n", __func__, *sptep);
 	pgprintk("instantiating %s PTE (%s) at %llx (%llx) addr %p\n",
 		 is_large_pte(*sptep)? "2MB" : "4kB",
@@ -3102,6 +3202,7 @@
 		++sp->root_count;
 		spin_unlock(&vcpu->kvm->mmu_lock);
 		vcpu->arch.mmu.root_hpa = __pa(sp->spt);
+//printk("PMC: tdp root %llu\n", vcpu->arch.mmu.root_hpa);
 	} else if (vcpu->arch.mmu.shadow_root_level == PT32E_ROOT_LEVEL) {
 		for (i = 0; i < 4; ++i) {
 			hpa_t root = vcpu->arch.mmu.pae_root[i];
@@ -3154,6 +3255,7 @@
 		++sp->root_count;
 		spin_unlock(&vcpu->kvm->mmu_lock);
 		vcpu->arch.mmu.root_hpa = root;
+//printk("PMC: spt root %llu\n", vcpu->arch.mmu.root_hpa);
 		return 0;
 	}
 
@@ -3290,7 +3392,8 @@
 __is_rsvd_bits_set(struct rsvd_bits_validate *rsvd_check, u64 pte, int level)
 {
 	int bit7 = (pte >> 7) & 1, low6 = pte & 0x3f;
-
+//printk("TDP: bit7 - %d, pte - %llu, low6 - %d, level - %d\n", bit7, pte, low6, level);
+//printk("TDP: rsvd_bit_mask - %llu, bad_mt_xwr - %llu\n", rsvd_check->rsvd_bits_mask[bit7][level-1], rsvd_check->bad_mt_xwr);
 	return (pte & rsvd_check->rsvd_bits_mask[bit7][level-1]) |
 		((rsvd_check->bad_mt_xwr & (1ull << low6)) != 0);
 }
@@ -3494,7 +3597,7 @@
 
 	if (unlikely(error_code & PFERR_RSVD_MASK)) {
 		r = handle_mmio_page_fault(vcpu, gpa, true);
-
+//printk("PMC: pos1 r=%d\n", r);
 		if (likely(r != RET_MMIO_PF_INVALID))
 			return r;
 	}
@@ -3534,7 +3637,7 @@
 	r = __direct_map(vcpu, gpa, write, map_writable,
 			 level, gfn, pfn, prefault);
 	spin_unlock(&vcpu->kvm->mmu_lock);
-
+//printk("PMC: pos3 r=%d\n", r);
 	return r;
 
 out_unlock:
@@ -3624,7 +3727,7 @@
 	u64 nonleaf_bit8_rsvd = 0;
 
 	rsvd_check->bad_mt_xwr = 0;
-
+//printk("TDP: %s is taken\n", __func__);
 	if (!nx)
 		exb_bit_rsvd = rsvd_bits(63, 63);
 	if (!gbpages)
@@ -3710,7 +3813,7 @@
 			    int maxphyaddr, bool execonly)
 {
 	u64 bad_mt_xwr;
-
+//printk("TDP: %s is taken\n", __func__);
 	rsvd_check->rsvd_bits_mask[0][3] =
 		rsvd_bits(maxphyaddr, 51) | rsvd_bits(3, 7);
 	rsvd_check->rsvd_bits_mask[0][2] =
@@ -3771,6 +3874,7 @@
 static inline bool boot_cpu_is_amd(void)
 {
 	WARN_ON_ONCE(!tdp_enabled);
+//printk("TDP: shadow_x_mask = %llu", shadow_x_mask);
 	return shadow_x_mask == 0;
 }
 
@@ -3943,7 +4047,7 @@
 	paging64_init_context_common(vcpu, context, PT32E_ROOT_LEVEL);
 }
 
-static void init_kvm_tdp_mmu(struct kvm_vcpu *vcpu)
+void init_kvm_tdp_mmu(struct kvm_vcpu *vcpu)
 {
 	struct kvm_mmu *context = &vcpu->arch.mmu;
 
@@ -3985,6 +4089,7 @@
 	update_permission_bitmask(vcpu, context, false);
 	update_last_pte_bitmap(vcpu, context);
 	reset_tdp_shadow_zero_bits_mask(vcpu, context);
+//printk("PMC: %s\n", __func__);
 }
 
 void kvm_init_shadow_mmu(struct kvm_vcpu *vcpu)
@@ -4040,7 +4145,7 @@
 }
 EXPORT_SYMBOL_GPL(kvm_init_shadow_ept_mmu);
 
-static void init_kvm_softmmu(struct kvm_vcpu *vcpu)
+void init_kvm_softmmu(struct kvm_vcpu *vcpu)
 {
 	struct kvm_mmu *context = &vcpu->arch.mmu;
 
@@ -4049,6 +4154,7 @@
 	context->get_cr3           = get_cr3;
 	context->get_pdptr         = kvm_pdptr_read;
 	context->inject_page_fault = kvm_inject_page_fault;
+//printk("PMC: %s\n", __func__);
 }
 
 static void init_kvm_nested_mmu(struct kvm_vcpu *vcpu)
@@ -4322,32 +4428,60 @@
 	spin_lock(&vcpu->kvm->mmu_lock);
 	++vcpu->kvm->stat.mmu_pte_write;
 	kvm_mmu_audit(vcpu, AUDIT_PRE_PTE_WRITE);
+	if (vcpu->arch.mmu.direct_map) {
+		for_each_gfn_indirect_valid_sp_tdp(vcpu->kvm, sp, gfn) {
+			if (detect_write_misaligned(sp, gpa, bytes) ||
+			      detect_write_flooding(sp)) {
+				zap_page |= !!kvm_mmu_prepare_zap_page(vcpu->kvm, sp,
+							     &invalid_list);
+				++vcpu->kvm->stat.mmu_flooded;
+				continue;
+			}
 
-	for_each_gfn_indirect_valid_sp(vcpu->kvm, sp, gfn) {
-		if (detect_write_misaligned(sp, gpa, bytes) ||
-		      detect_write_flooding(sp)) {
-			zap_page |= !!kvm_mmu_prepare_zap_page(vcpu->kvm, sp,
-						     &invalid_list);
-			++vcpu->kvm->stat.mmu_flooded;
-			continue;
-		}
-
-		spte = get_written_sptes(sp, gpa, &npte);
-		if (!spte)
-			continue;
+			spte = get_written_sptes(sp, gpa, &npte);
+			if (!spte)
+				continue;
 
-		local_flush = true;
-		while (npte--) {
-			entry = *spte;
-			mmu_page_zap_pte(vcpu->kvm, sp, spte);
-			if (gentry &&
-			      !((sp->role.word ^ vcpu->arch.mmu.base_role.word)
-			      & mask.word) && rmap_can_add(vcpu))
-				mmu_pte_write_new_pte(vcpu, sp, spte, &gentry);
-			if (need_remote_flush(entry, *spte))
-				remote_flush = true;
-			++spte;
+			local_flush = true;
+			while (npte--) {
+				entry = *spte;
+				mmu_page_zap_pte(vcpu->kvm, sp, spte);
+				if (gentry &&
+				      !((sp->role.word ^ vcpu->arch.mmu.base_role.word)
+				      & mask.word) && rmap_can_add(vcpu))
+					mmu_pte_write_new_pte(vcpu, sp, spte, &gentry);
+				if (need_remote_flush(entry, *spte))
+					remote_flush = true;
+				++spte;
+			}
 		}
+	} else  {
+	        for_each_gfn_indirect_valid_sp_spt(vcpu->kvm, sp, gfn) {
+        	        if (detect_write_misaligned(sp, gpa, bytes) ||
+	                      detect_write_flooding(sp)) {
+	                        zap_page |= !!kvm_mmu_prepare_zap_page(vcpu->kvm, sp,
+                                	                     &invalid_list);
+                        	++vcpu->kvm->stat.mmu_flooded;
+                	        continue;
+        	        }
+
+	                spte = get_written_sptes(sp, gpa, &npte);
+                	if (!spte)
+        	                continue;
+
+	                local_flush = true;
+	                while (npte--) {
+                        	entry = *spte;
+                        	mmu_page_zap_pte(vcpu->kvm, sp, spte);
+                	        if (gentry &&
+        	                      !((sp->role.word ^ vcpu->arch.mmu.base_role.word)
+	                              & mask.word) && rmap_can_add(vcpu))
+                                mmu_pte_write_new_pte(vcpu, sp, spte, &gentry);
+	                        if (need_remote_flush(entry, *spte))
+                        	        remote_flush = true;
+                	        ++spte;
+        	        }
+	        }
 	}
 	mmu_pte_write_flush_tlb(vcpu, zap_page, remote_flush, local_flush);
 	kvm_mmu_commit_zap_page(vcpu->kvm, &invalid_list);
@@ -4412,7 +4546,7 @@
 
 	if (is_mmio_page_fault(vcpu, cr2))
 		emulation_type = 0;
-
+//printk("PMC: cr2=%lu, emt=%d, ilen=%d\n", cr2, emulation_type, insn_len);
 	er = x86_emulate_instruction(vcpu, cr2, emulation_type, insn, insn_len);
 
 	switch (er) {
@@ -4809,6 +4943,16 @@
 	spin_unlock(&kvm->mmu_lock);
 }
 
+/* Make request to reload mmu for PM switching */
+void kvm_mmu_pms_request(struct kvm *kvm, int paging_method)
+{
+//printk("PMC: %s is called with %d\n", __func__, paging_method);
+	if (!paging_method)
+	        kvm_mmu_invalidate_zap_all_pages(kvm);		
+	else
+		kvm_reload_remote_mmus(kvm);
+}
+
 static bool kvm_has_zapped_obsolete_pages(struct kvm *kvm)
 {
 	return unlikely(!list_empty_careful(&kvm->arch.zapped_obsolete_pages));
Only in linux-4.4.13.b/arch/x86/kvm: mmu.c.new
diff -u linux-4.4.13/arch/x86/kvm/mmu.h linux-4.4.13.b/arch/x86/kvm/mmu.h
--- linux-4.4.13/arch/x86/kvm/mmu.h	2016-06-08 03:14:51.000000000 +0200
+++ linux-4.4.13.b/arch/x86/kvm/mmu.h	2016-11-10 19:31:04.000000000 +0100
@@ -84,12 +84,36 @@
 	return 0;
 }
 
-static inline int kvm_mmu_reload(struct kvm_vcpu *vcpu)
+/*static inline int kvm_mmu_reload(struct kvm_vcpu *vcpu)
 {
 	if (likely(vcpu->arch.mmu.root_hpa != INVALID_PAGE))
 		return 0;
 
 	return kvm_mmu_load(vcpu);
+}*/
+
+static inline int kvm_mmu_reload(struct kvm_vcpu *vcpu)
+{
+	int need_switch;
+	int direct_map;
+
+        need_switch = vcpu->kvm->arch.pmc.need_switch;
+        direct_map = vcpu->arch.mmu.direct_map;
+
+        if (likely(vcpu->arch.mmu.root_hpa != INVALID_PAGE))
+		if (!need_switch)
+	               	return 0;
+	if (need_switch && direct_map && !vcpu->vcpu_id) {
+		vcpu->kvm->arch.pmc.need_switch = 0;
+		kvm_x86_ops->tdp_to_spt(vcpu);
+		return 0;
+	}
+	else if (need_switch && !direct_map && !vcpu->vcpu_id) {
+		vcpu->kvm->arch.pmc.need_switch = 0;
+		kvm_x86_ops->spt_to_tdp(vcpu);
+		return 0;
+	}
+        return kvm_mmu_load(vcpu);
 }
 
 static inline int is_present_gpte(unsigned long pte)
Only in linux-4.4.13.b/arch/x86/kvm: mmu.h.new
Only in linux-4.4.13.b/arch/x86/kvm: paging_tmpl.h.new
diff -u linux-4.4.13/arch/x86/kvm/svm.c linux-4.4.13.b/arch/x86/kvm/svm.c
--- linux-4.4.13/arch/x86/kvm/svm.c	2016-06-08 03:14:51.000000000 +0200
+++ linux-4.4.13.b/arch/x86/kvm/svm.c	2016-12-20 17:40:02.214525995 +0100
@@ -3781,11 +3781,13 @@
 static void svm_vcpu_run(struct kvm_vcpu *vcpu)
 {
 	struct vcpu_svm *svm = to_svm(vcpu);
+        int pre_pm, cur_pm;
 
 	svm->vmcb->save.rax = vcpu->arch.regs[VCPU_REGS_RAX];
 	svm->vmcb->save.rsp = vcpu->arch.regs[VCPU_REGS_RSP];
 	svm->vmcb->save.rip = vcpu->arch.regs[VCPU_REGS_RIP];
 
+        pre_pm = vcpu->kvm->arch.pmc.paging_method;
 	/*
 	 * A vmexit emulation is required before the vcpu can be executed
 	 * again.
@@ -3928,6 +3930,12 @@
 		svm_handle_mce(svm);
 
 	mark_all_clean(svm->vmcb);
+
+        cur_pm = vcpu->kvm->arch.pmc.paging_method;
+        if (cur_pm != pre_pm) { /* if any change in paging method */
+                vcpu->kvm->arch.pmc.need_switch = 1;
+                kvm_make_all_cpus_request(vcpu->kvm, KVM_REQ_MMU_RELOAD);
+        }
 }
 
 static void svm_set_cr3(struct kvm_vcpu *vcpu, unsigned long root)
@@ -4260,6 +4268,93 @@
 {
 }
 
+static void vmcb_update(struct kvm_vcpu *vcpu)
+{
+        struct vcpu_svm *svm = to_svm(vcpu);
+	struct vmcb_control_area *control = &svm->vmcb->control;
+	struct vmcb_save_area *save = &svm->vmcb->save;
+
+//	save->cr4 = X86_CR4_PAE;
+	if (npt_enabled) {
+		/* Setup VMCB for Nested Paging */
+		control->nested_ctl = 1;
+		clr_intercept(svm, INTERCEPT_INVLPG);
+		clr_exception_intercept(svm, PF_VECTOR);
+		clr_cr_intercept(svm, INTERCEPT_CR3_READ);
+		clr_cr_intercept(svm, INTERCEPT_CR3_WRITE);
+		save->g_pat = svm->vcpu.arch.pat;
+		save->cr0 = vcpu->arch.cr0;
+//		save->cr3 = kvm_read_cr3(vcpu);
+		save->cr3 = vcpu->arch.cr3;
+		save->cr4 = vcpu->arch.cr4;
+	} else {
+	        control->nested_ctl = 0;
+        	set_intercept(svm, INTERCEPT_INVLPG);
+	        set_exception_intercept(svm, PF_VECTOR);
+        	set_cr_intercept(svm, INTERCEPT_CR3_READ);
+	        set_cr_intercept(svm, INTERCEPT_CR3_WRITE);
+		vcpu->arch.pat = MSR_IA32_CR_PAT_DEFAULT;
+	}
+}
+
+static int npt_to_spt(struct kvm_vcpu *vcpu)
+{
+        struct kvm *kvm = vcpu->kvm;
+        struct kvm_vcpu *v;
+        unsigned int i;
+//	DEFINE_WAIT(wait);
+
+        if (vcpu->vcpu_id)
+                return 0;
+        if (!vcpu->arch.mmu.direct_map)
+                return 0;
+//      kvm_guest_suspend(kvm, wait); /* suspend this guest */
+        npt_enabled = 0;
+        kvm_disable_tdp();
+        kvm_for_each_vcpu(i, v, kvm) {
+                kvm->arch.pmc.root_hpa[v->vcpu_id] = v->arch.mmu.root_hpa;
+                v->arch.mmu.root_hpa = INVALID_PAGE;
+                vmcb_update(v);
+                kvm_mmu_setup(v);
+                kvm_mmu_load(v);
+        }
+//      kvm_guest_restore(kvm, wait); /* restore this guest */
+printk("PMC: %s, npt_enabled=%d\n", __func__, npt_enabled);
+        return 0;
+}
+
+static int spt_to_npt(struct kvm_vcpu *vcpu)
+{
+        struct kvm *kvm = vcpu->kvm;
+        struct kvm_vcpu *v;
+        unsigned int i;
+        DEFINE_WAIT(wait);
+
+        if (vcpu->vcpu_id)
+                return 0;
+        if (vcpu->arch.mmu.direct_map)
+                return 0;
+//      kvm_guest_suspend(kvm, wait); /* suspend this guest */
+        npt_enabled = 1;
+        kvm_enable_tdp();
+        kvm_for_each_vcpu(i, v, kvm) {
+                kvm_mmu_unload(v);
+                vmcb_update(v);
+                kvm_mmu_setup(v);
+                if (kvm->arch.pmc.first_time) {
+                        kvm->arch.pmc.first_time = 0;
+                        kvm_mmu_load(vcpu);
+                }
+                else {
+                        v->arch.mmu.root_hpa = kvm->arch.pmc.root_hpa[v->vcpu_id];
+                        svm_set_cr3(vcpu, v->arch.mmu.root_hpa);
+                }
+        }
+//      kvm_guest_restore(kvm, wait); /* restore this guest */
+printk("PMC: %s, npt_enabled=%d\n", __func__, npt_enabled);
+        return 0;
+}
+
 static struct kvm_x86_ops svm_x86_ops = {
 	.cpu_has_kvm_support = has_svm,
 	.disabled_by_bios = is_disabled,
@@ -4364,6 +4459,9 @@
 	.sched_in = svm_sched_in,
 
 	.pmu_ops = &amd_pmu_ops,
+
+        .spt_to_tdp = spt_to_npt,
+        .tdp_to_spt = npt_to_spt,
 };
 
 static int __init svm_init(void)
Only in linux-4.4.13.b/arch/x86/kvm: svm.c~
diff -u linux-4.4.13/arch/x86/kvm/vmx.c linux-4.4.13.b/arch/x86/kvm/vmx.c
--- linux-4.4.13/arch/x86/kvm/vmx.c	2016-06-08 03:14:51.000000000 +0200
+++ linux-4.4.13.b/arch/x86/kvm/vmx.c	2016-11-10 19:31:04.000000000 +0100
@@ -5936,6 +5936,7 @@
 
 	ret = handle_mmio_page_fault(vcpu, gpa, true);
 	if (likely(ret == RET_MMIO_PF_EMULATE))
+//printk("PMC: in %s\n", __func__);
 		return x86_emulate_instruction(vcpu, gpa, 0, NULL, 0) ==
 					      EMULATE_DONE;
 
@@ -5999,6 +6000,7 @@
 			vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
 			vcpu->run->internal.suberror = KVM_INTERNAL_ERROR_EMULATION;
 			vcpu->run->internal.ndata = 0;
+//printk("PMC: in %s\n", __func__);
 			return 0;
 		}
 
@@ -8528,7 +8530,9 @@
 {
 	struct vcpu_vmx *vmx = to_vmx(vcpu);
 	unsigned long debugctlmsr, cr4;
+	int pre_pm, cur_pm;
 
+	pre_pm = vcpu->kvm->arch.pmc.paging_method;
 	/* Record the guest's net vcpu time for enforced NMI injections. */
 	if (unlikely(!cpu_has_virtual_nmis() && vmx->soft_vnmi_blocked))
 		vmx->entry_time = ktime_get();
@@ -8719,6 +8723,12 @@
 	vmx_complete_atomic_exit(vmx);
 	vmx_recover_nmi_blocking(vmx);
 	vmx_complete_interrupts(vmx);
+
+	cur_pm = vcpu->kvm->arch.pmc.paging_method;
+	if (cur_pm != pre_pm) { /* if any change in paging method */
+		vcpu->kvm->arch.pmc.need_switch = 1;
+		kvm_make_all_cpus_request(vcpu->kvm, KVM_REQ_MMU_RELOAD);
+	}
 }
 
 static void vmx_load_vmcs01(struct kvm_vcpu *vcpu)
@@ -10772,6 +10782,133 @@
 	return ret;
 }
 
+static void vmcs_update(struct kvm_vcpu *vcpu)
+{
+	struct vcpu_vmx *vmx = to_vmx(vcpu);
+	u32 exec_control, sec_exec_ctl;
+	u32 eb;
+	u64 mask;
+	int maxphyaddr = boot_cpu_data.x86_phys_bits;
+
+	eb = vmcs_read32(EXCEPTION_BITMAP);
+	if (enable_ept)
+		eb &= ~(1u << PF_VECTOR);
+	else
+		eb |= (1u << PF_VECTOR);
+	vmcs_write32(EXCEPTION_BITMAP, eb);
+
+	mask = rsvd_bits(maxphyaddr, 51);
+	mask |= 0x3ull << 62;
+	mask |= 1ull;
+#ifdef CONFIG_X86_64
+	if (maxphyaddr == 52)
+	mask &= ~1ull;
+#endif
+	kvm_mmu_set_mmio_spte_mask(mask);
+
+	kvm_mmu_set_mask_ptes(PT_USER_MASK, PT_ACCESSED_MASK,
+			PT_DIRTY_MASK, PT64_NX_MASK, 0);
+	if (enable_ept) {
+		if (!vcpu->kvm->arch.ept_identity_map_addr)
+			vcpu->kvm->arch.ept_identity_map_addr =
+			VMX_EPT_IDENTITY_PAGETABLE_ADDR;
+		init_rmode_identity_map(vcpu->kvm);
+
+                kvm_mmu_set_mask_ptes(0ull,
+                        (enable_ept_ad_bits) ? VMX_EPT_ACCESS_BIT : 0ull,
+                        (enable_ept_ad_bits) ? VMX_EPT_DIRTY_BIT : 0ull,
+                        0ull, VMX_EPT_EXECUTABLE_MASK);
+		ept_set_mmio_spte_mask();
+        }
+
+        exec_control = vmx_exec_control(vmx);
+	if (enable_ept)
+		exec_control &= ~(CPU_BASED_CR3_STORE_EXITING |
+				  CPU_BASED_CR3_LOAD_EXITING  |
+				  CPU_BASED_INVLPG_EXITING);
+        vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, exec_control);
+
+	if (!enable_ept || !enable_ept_ad_bits || !cpu_has_vmx_pml())
+		enable_pml = 0;
+	if (!enable_pml) {
+		kvm_x86_ops->slot_enable_log_dirty = NULL;
+		kvm_x86_ops->slot_disable_log_dirty = NULL;
+		kvm_x86_ops->flush_log_dirty = NULL;
+		kvm_x86_ops->enable_log_dirty_pt_masked = NULL;
+	} 
+	else {
+		vmx_create_pml_buffer(vmx);
+	        kvm_x86_ops->slot_enable_log_dirty = vmx_slot_enable_log_dirty;
+        	kvm_x86_ops->slot_disable_log_dirty = vmx_slot_disable_log_dirty;
+	        kvm_x86_ops->flush_log_dirty = vmx_flush_log_dirty;
+        	kvm_x86_ops->enable_log_dirty_pt_masked = vmx_enable_log_dirty_pt_masked;
+	}
+
+	setup_msrs(vmx); // newly added
+	sec_exec_ctl = vmx_secondary_exec_control(vmx);
+	vmcs_write32(SECONDARY_VM_EXEC_CONTROL, sec_exec_ctl);
+}
+
+/* PM switching implementation */
+static int spt_to_ept(struct kvm_vcpu *vcpu)
+{
+        struct kvm *kvm = vcpu->kvm;
+	struct kvm_vcpu *v;
+        unsigned int i;
+//	int r;
+        DEFINE_WAIT(wait);
+
+        if (vcpu->vcpu_id)
+		return 0;
+	if (vcpu->arch.mmu.direct_map)
+                return 0;
+//	kvm_guest_suspend(kvm, wait); /* suspend this guest */
+        enable_ept = 1;
+	kvm_enable_tdp();
+	kvm_for_each_vcpu(i, v, kvm) {
+		kvm_mmu_unload(v);
+		vmcs_update(v);
+		kvm_mmu_setup(v);
+		if (kvm->arch.pmc.first_time) {
+			kvm->arch.pmc.first_time = 0;
+			kvm_mmu_load(vcpu);
+		}
+		else {
+	               	v->arch.mmu.root_hpa = kvm->arch.pmc.root_hpa[v->vcpu_id];
+			vmx_set_cr3(vcpu, v->arch.mmu.root_hpa);
+		}
+	}
+//	kvm_guest_restore(kvm, wait); /* restore this guest */
+printk("PMC: %s, enable_ept=%d\n", __func__, enable_ept);
+        return 0;
+}
+
+static int ept_to_spt(struct kvm_vcpu *vcpu)
+{
+        struct kvm *kvm = vcpu->kvm;
+	struct kvm_vcpu *v;
+        unsigned int i;
+        DEFINE_WAIT(wait);
+
+	if (vcpu->vcpu_id)
+		return 0;
+	if (!vcpu->arch.mmu.direct_map)
+                return 0;
+//	kvm_guest_suspend(kvm, wait); /* suspend this guest */
+	enable_ept = 0;
+	kvm_disable_tdp();
+        kvm_for_each_vcpu(i, v, kvm) {
+		kvm->arch.pmc.root_hpa[v->vcpu_id] = v->arch.mmu.root_hpa;
+		v->arch.mmu.root_hpa = INVALID_PAGE;
+		vmcs_update(v);
+		kvm_mmu_setup(v);
+                kvm_mmu_load(vcpu);
+	}
+//	kvm_guest_restore(kvm, wait); /* restore this guest */
+printk("PMC: %s, enable_ept=%d\n", __func__, enable_ept);
+        return 0;
+}
+
 static struct kvm_x86_ops vmx_x86_ops = {
 	.cpu_has_kvm_support = cpu_has_kvm_support,
 	.disabled_by_bios = vmx_disabled_by_bios,
@@ -10892,12 +11029,15 @@
 	.pmu_ops = &intel_pmu_ops,
 
 	.update_pi_irte = vmx_update_pi_irte,
+	.spt_to_tdp = spt_to_ept,
+	.tdp_to_spt = ept_to_spt,
 };
 
 static int __init vmx_init(void)
 {
 	int r = kvm_init(&vmx_x86_ops, sizeof(struct vcpu_vmx),
                      __alignof__(struct vcpu_vmx), THIS_MODULE);
+printk("PMC: %s called\n", __func__);
 	if (r)
 		return r;
 
@@ -10917,6 +11057,7 @@
 #endif
 
 	kvm_exit();
+printk("PMC: %s called\n", __func__);
 }
 
 module_init(vmx_init)
diff -u linux-4.4.13/arch/x86/kvm/x86.c linux-4.4.13.b/arch/x86/kvm/x86.c
--- linux-4.4.13/arch/x86/kvm/x86.c	2016-06-08 03:14:51.000000000 +0200
+++ linux-4.4.13.b/arch/x86/kvm/x86.c	2016-12-20 13:54:08.020297554 +0100
@@ -67,6 +67,7 @@
 #include <asm/pvclock.h>
 #include <asm/div64.h>
 #include <asm/irq_remapping.h>
+#include <asm/pmc_test.h>
 
 #define MAX_IO_MSRS 256
 #define KVM_MAX_MCE_BANKS 32
@@ -5098,7 +5099,7 @@
 		r = EMULATE_FAIL;
 	}
 	kvm_queue_exception(vcpu, UD_VECTOR);
-
+//printk("PMC: in %s\n", __func__);
 	return r;
 }
 
@@ -5385,6 +5386,7 @@
 				return EMULATE_DONE;
 			if (emulation_type & EMULTYPE_SKIP)
 				return EMULATE_FAIL;
+//printk("PMC: %s pos1\n", __func__);
 			return handle_emulation_failure(vcpu);
 		}
 	}
@@ -5416,7 +5418,7 @@
 		if (reexecute_instruction(vcpu, cr2, write_fault_to_spt,
 					emulation_type))
 			return EMULATE_DONE;
-
+printk("PMC: %s pos2\n", __func__);
 		return handle_emulation_failure(vcpu);
 	}
 
@@ -6369,10 +6371,13 @@
 		kvm_cpu_accept_dm_intr(vcpu);
 
 	bool req_immediate_exit = false;
-
+	
 	if (vcpu->requests) {
-		if (kvm_check_request(KVM_REQ_MMU_RELOAD, vcpu))
-			kvm_mmu_unload(vcpu);
+		if (kvm_check_request(KVM_REQ_MMU_RELOAD, vcpu)) {
+//			printk("PMC: VCPU %d has root %llu\n", vcpu->vcpu_id, vcpu->arch.mmu.root_hpa);
+			if (!vcpu->kvm->arch.pmc.need_switch)
+				kvm_mmu_unload(vcpu);
+		}
 		if (kvm_check_request(KVM_REQ_MIGRATE_TIMER, vcpu))
 			__kvm_migrate_timers(vcpu);
 		if (kvm_check_request(KVM_REQ_MASTERCLOCK_UPDATE, vcpu))
@@ -6483,12 +6488,12 @@
 			kvm_lapic_sync_to_vapic(vcpu);
 		}
 	}
-
+	
 	r = kvm_mmu_reload(vcpu);
+
 	if (unlikely(r)) {
 		goto cancel_injection;
 	}
-
 	preempt_disable();
 
 	kvm_x86_ops->prepare_guest_switch(vcpu);
@@ -6536,7 +6541,6 @@
 	}
 
 	kvm_x86_ops->run(vcpu);
-
 	/*
 	 * Do this here before restoring debug registers on the host.  And
 	 * since we do this before handling the vmexit, a DR access vmexit
@@ -6820,7 +6824,7 @@
 		WARN_ON(vcpu->arch.pio.count || vcpu->mmio_needed);
 
 	r = vcpu_run(vcpu);
-
+//printk("PMC: r in %s is %d\n", __func__, r);
 out:
 	post_kvm_run_save(vcpu);
 	if (vcpu->sigset_active)
@@ -7619,6 +7623,22 @@
 	kvm_x86_ops->sched_in(vcpu, cpu);
 }
 
+/*void timer_routine(unsigned long data)
+{
+	int i;
+	unsigned long r[4];
+	struct kvm *kvm;
+	kvm = (struct kvm *)data;
+	for (i=0; i<4; i++)
+		r[i] = kvm->vcpus[0]->arch.regs[12 + i];
+
+        printk(KERN_INFO "PMC: %lu  %lu  %lu  %lu\n", r[0], r[1], r[2], r[3]);
+        kvm->arch.timer.expires = jiffies + msecs_to_jiffies(1000);
+        add_timer(&kvm->arch.timer);
+
+        return;
+}*/
+
 int kvm_arch_init_vm(struct kvm *kvm, unsigned long type)
 {
 	if (type)
@@ -7628,6 +7648,7 @@
 	INIT_LIST_HEAD(&kvm->arch.active_mmu_pages);
 	INIT_LIST_HEAD(&kvm->arch.zapped_obsolete_pages);
 	INIT_LIST_HEAD(&kvm->arch.assigned_dev_head);
+//	INIT_LIST_HEAD(&kvm->arch.page_entity_list);
 	atomic_set(&kvm->arch.noncoherent_dma_count, 0);
 
 	/* Reserve bit 0 of irq_sources_bitmap for userspace irq source */
@@ -7645,6 +7666,7 @@
 	INIT_DELAYED_WORK(&kvm->arch.kvmclock_update_work, kvmclock_update_fn);
 	INIT_DELAYED_WORK(&kvm->arch.kvmclock_sync_work, kvmclock_sync_fn);
 
+        pmc_start(kvm, 1 << 1); /* Try to start the PMCs  */
 	return 0;
 }
 
@@ -7771,6 +7793,8 @@
 	kfree(kvm->arch.vioapic);
 	kvm_free_vcpus(kvm);
 	kfree(rcu_dereference_check(kvm->arch.apic_map, 1));
+
+	pmc_stop(kvm, 1 << 1); /* Try to stop the PMCs */
 }
 
 void kvm_arch_free_memslot(struct kvm *kvm, struct kvm_memory_slot *free,
Only in linux-4.4.13.b/arch/x86/kvm: x86.c~
Only in linux-4.4.13.b/arch/x86/kvm: x86.c.orig
Common subdirectories: linux-4.4.13/virt/kvm/arm and linux-4.4.13.b/virt/kvm/arm
diff -u linux-4.4.13/virt/kvm/kvm_main.c linux-4.4.13.b/virt/kvm/kvm_main.c
--- linux-4.4.13/virt/kvm/kvm_main.c	2016-06-08 03:14:51.000000000 +0200
+++ linux-4.4.13.b/virt/kvm/kvm_main.c	2016-12-20 13:02:26.496527374 +0100
@@ -55,6 +55,7 @@
 #include <asm/ioctl.h>
 #include <asm/uaccess.h>
 #include <asm/pgtable.h>
+//#include <asm/pmc_test.h>
 
 #include "coalesced_mmio.h"
 #include "async_pf.h"
@@ -693,6 +694,7 @@
 	kvm_irqfd_release(kvm);
 
 	kvm_put_kvm(kvm);
+printk("PMC: %s invoked\n", __func__);
 	return 0;
 }
 
@@ -2106,6 +2108,47 @@
 }
 EXPORT_SYMBOL_GPL(kvm_vcpu_yield_to);
 
+/* Operations to suspend and restore a vcpu */
+void kvm_vcpu_suspend(struct kvm_vcpu *vcpu, wait_queue_t wait)
+{
+	prepare_to_wait(&vcpu->wq, &wait, TASK_INTERRUPTIBLE);
+	if (!vcpu->kvm->arch.pmc.pm_ready) {
+		printk("PMC: vcpu %d sleeps\n", vcpu->vcpu_id);
+		schedule();
+	}
+	return;	
+}
+
+void kvm_vcpu_restore(struct kvm_vcpu *vcpu, wait_queue_t wait)
+{
+	finish_wait(&vcpu->wq, &wait);
+	printk("PMC: vcpu %d awaken\n", vcpu->vcpu_id);
+	return;	
+}
+
+/* Operations to suspend and resore a kvm guest */
+void kvm_guest_suspend(struct kvm *kvm, wait_queue_t wait)
+{
+        int i;
+        struct kvm_vcpu *vcpu;
+	kvm->arch.pmc.pm_ready = 0;
+	kvm_for_each_vcpu(i, vcpu, kvm) {
+		kvm_vcpu_suspend(vcpu, wait);
+	}	
+	return;	
+}
+
+void kvm_guest_restore(struct kvm *kvm, wait_queue_t wait)
+{
+	int i;
+	struct kvm_vcpu *vcpu;
+	kvm->arch.pmc.pm_ready = 1;
+	kvm_for_each_vcpu(i, vcpu, kvm) {
+	        kvm_vcpu_restore(vcpu, wait);
+	}
+	return;
+}
+
 /*
  * Helper that checks whether a VCPU is eligible for directed yield.
  * Most eligible candidate to yield is decided by following heuristics:
@@ -2234,6 +2277,7 @@
 	struct kvm_vcpu *vcpu = filp->private_data;
 
 	kvm_put_kvm(vcpu->kvm);
+printk("PMC: %s invoked\n", __func__);
 	return 0;
 }
 
@@ -2269,7 +2313,7 @@
 	vcpu = kvm_arch_vcpu_create(kvm, id);
 	if (IS_ERR(vcpu))
 		return PTR_ERR(vcpu);
-
+//printk("PMC: vcpu %p, %p, %p\n", (void *)vcpu, (void *)&vcpu->arch.regs[0], (void *)&vcpu->arch.regs[1]);
 	preempt_notifier_init(&vcpu->preempt_notifier, &kvm_preempt_ops);
 
 	r = kvm_arch_vcpu_setup(vcpu);
@@ -2313,6 +2357,9 @@
 
 	mutex_unlock(&kvm->lock);
 	kvm_arch_vcpu_postcreate(vcpu);
+
+//	if (id == 0)
+//		pmc_start(kvm, 1 << 1); /*try to start the PMCs  */
 	return r;
 
 unlock_vcpu_destroy:
@@ -2623,6 +2670,7 @@
 	struct kvm *kvm = dev->kvm;
 
 	kvm_put_kvm(kvm);
+printk("PMC: %s invoked\n", __func__);
 	return 0;
 }
 
Only in linux-4.4.13.b/virt/kvm: kvm_main.c~
Only in linux-4.4.13.b/virt/kvm: kvm_main.c.orig
--- linux-4.4.13/arch/x86/include/asm/kvm_host.h	2016-06-08 03:14:51.000000000 +0200
+++ linux-4.4.13.b/arch/x86/include/asm/kvm_host.h	2016-11-10 19:30:54.000000000 +0100
@@ -352,6 +352,45 @@
 	u64 reprogram_pmi;
 };
 
+enum {
+	PM_SPT = 0,
+	PM_EPT = 1,
+	PM_NPT = 2,
+};
+
+struct pmc_val_t {
+        unsigned long itmis;
+        unsigned long dtmis;
+        unsigned long instr;
+        unsigned long cycle;
+//	unsigned long pf_fixed1;   /* last pf_fixed     */
+//	unsigned long pf_fixed2;   /* current pf_fixed  */
+//	unsigned long exits1;
+//	unsigned long exits2;
+
+        unsigned long cur_ipc;     /* current IPC value */
+        unsigned long cur_pfr;     /* current PFR value */
+        unsigned long cur_tmr;     /* current TMR value */
+
+	struct {
+		unsigned long his_ipc;
+		unsigned long his_pfr;
+		unsigned long his_tmr;
+	} his[10];		   /* recent 10 values  */
+
+        unsigned long sum_ipc;     /* sum of IPC values */
+        unsigned long sum_pfr;     /* sum of PFR values */
+        unsigned long sum_tmr;     /* sum of TMR values */
+
+        unsigned long num;         /* number of values  */
+	int paging_method;	   /* the desired pm    */
+	int need_switch;	   /* need to switch    */
+	int pm_ready;		   /* indicate pm ready */
+	int first_time;
+	
+	hpa_t root_hpa[4];	   /* hpa root for pm   */
+};
+
 struct kvm_pmu_ops;
 
 enum {
@@ -629,7 +668,9 @@
 	unsigned int n_max_mmu_pages;
 	unsigned int indirect_shadow_pages;
 	unsigned long mmu_valid_gen;
-	struct hlist_head mmu_page_hash[KVM_NUM_MMU_PAGES];
+//	struct hlist_head mmu_page_hash[KVM_NUM_MMU_PAGES];
+	struct hlist_head mmu_spt_hash[KVM_NUM_MMU_PAGES]; /* For SPT*/
+	struct hlist_head mmu_tdp_hash[KVM_NUM_MMU_PAGES]; /* For EPT or NPT */
 	/*
 	 * Hash table of struct kvm_mmu_page.
 	 */
@@ -695,6 +736,9 @@
 
 	bool irqchip_split;
 	u8 nr_reserved_ioapic_pins;
+
+	struct pmc_val_t pmc;
+	struct timer_list timer;
 };
 
 struct kvm_vm_stat {
@@ -911,6 +955,8 @@
 	void (*post_block)(struct kvm_vcpu *vcpu);
 	int (*update_pi_irte)(struct kvm *kvm, unsigned int host_irq,
 			      uint32_t guest_irq, bool set);
+	int (*spt_to_tdp)(struct kvm_vcpu *vcpu);
+	int (*tdp_to_spt)(struct kvm_vcpu *vcpu);
 };
 
 struct kvm_arch_async_pf {
