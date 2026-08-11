import React, { useState } from 'react';
import {
	ActivityIndicator,
	Platform,
	StyleSheet,
	Text,
	TextInput,
	TouchableOpacity,
	View
} from 'react-native';
import { useAdminSession } from '../context/AdminSessionContext';
import {
	adminGetAccountInfo,
	adminGetSubjectStatus,
	adminSetAccountInvitesEnabled,
	adminSetDeactivated,
	adminSetTakedown,
	resolveHandle,
	type AdminAccountView,
	type SubjectStatus
} from '../api/pds';
import { colors } from '../theme';

export function AccountLookup() {
	const { session } = useAdminSession();
	const [input, setInput] = useState('');
	const [pending, setPending] = useState(false);
	const [error, setError] = useState('');
	const [account, setAccount] = useState<AdminAccountView | null>(null);
	const [status, setStatus] = useState<SubjectStatus | null>(null);
	const [actionPending, setActionPending] = useState(false);
	const [actionError, setActionError] = useState('');

	if (!session) return null;

	async function handleLookup() {
		setError('');
		setPending(true);
		setAccount(null);
		setStatus(null);
		try {
			const did = input.startsWith('did:') ? input : await resolveHandle(session!, input);
			const [info, subj] = await Promise.all([
				adminGetAccountInfo(session!, did),
				adminGetSubjectStatus(session!, did)
			]);
			setAccount(info);
			setStatus(subj);
		} catch (err) {
			setError(err instanceof Error ? err.message : 'Account not found');
		} finally {
			setPending(false);
		}
	}

	async function refresh(did: string) {
		const [info, subj] = await Promise.all([
			adminGetAccountInfo(session!, did),
			adminGetSubjectStatus(session!, did)
		]);
		setAccount(info);
		setStatus(subj);
	}

	async function runAction(fn: () => Promise<void>) {
		if (!account) return;
		setActionError('');
		setActionPending(true);
		try {
			await fn();
			await refresh(account.did);
		} catch (err) {
			setActionError(err instanceof Error ? err.message : 'Action failed');
		} finally {
			setActionPending(false);
		}
	}

	return (
		<View style={styles.section}>
			<Text style={styles.sectionTitle}>ACCOUNT LOOKUP</Text>

			<View style={styles.row}>
				<TextInput
					value={input}
					onChangeText={setInput}
					placeholder="did:plc:… or handle"
					placeholderTextColor={colors.textMuted}
					autoCapitalize="none"
					autoCorrect={false}
					style={[styles.input, styles.flex]}
					onSubmitEditing={handleLookup}
				/>
				<TouchableOpacity
					style={[styles.smallButton, (pending || !input) && styles.buttonDisabled]}
					disabled={pending || !input}
					onPress={handleLookup}
				>
					{pending ? (
						<ActivityIndicator color={colors.buttonText} size="small" />
					) : (
						<Text style={styles.smallButtonText}>Look up</Text>
					)}
				</TouchableOpacity>
			</View>

			{error ? <Text style={styles.error}>{error}</Text> : null}

			{account && (
				<View style={styles.accountBlock}>
					<Field label="Handle" value={account.handle} mono />
					<Field label="DID" value={account.did} mono />
					{account.email ? <Field label="Email" value={account.email} /> : null}
					<Field label="Indexed" value={account.indexedAt} />

					<View style={styles.actionsRow}>
						<TouchableOpacity
							disabled={actionPending}
							onPress={() =>
								runAction(() => adminSetTakedown(session!, account.did, !status?.takedown?.applied))
							}
							style={[
								styles.pill,
								status?.takedown?.applied ? styles.pillDanger : styles.pillNeutral,
								actionPending && styles.buttonDisabled
							]}
						>
							<Text
								style={status?.takedown?.applied ? styles.pillDangerText : styles.pillNeutralText}
							>
								{status?.takedown?.applied ? 'Remove takedown' : 'Take down'}
							</Text>
						</TouchableOpacity>

						<TouchableOpacity
							disabled={actionPending}
							onPress={() =>
								runAction(() =>
									adminSetDeactivated(session!, account.did, !status?.deactivated?.applied)
								)
							}
							style={[
								styles.pill,
								status?.deactivated?.applied ? styles.pillWarning : styles.pillNeutral,
								actionPending && styles.buttonDisabled
							]}
						>
							<Text
								style={
									status?.deactivated?.applied ? styles.pillWarningText : styles.pillNeutralText
								}
							>
								{status?.deactivated?.applied ? 'Reactivate' : 'Deactivate'}
							</Text>
						</TouchableOpacity>

						<TouchableOpacity
							disabled={actionPending}
							onPress={() =>
								runAction(() =>
									adminSetAccountInvitesEnabled(session!, account.did, !!account.invitesDisabled)
								)
							}
							style={[styles.pill, styles.pillNeutral, actionPending && styles.buttonDisabled]}
						>
							<Text style={styles.pillNeutralText}>
								{account.invitesDisabled ? 'Enable invites' : 'Disable invites'}
							</Text>
						</TouchableOpacity>
					</View>

					{actionError ? <Text style={styles.error}>{actionError}</Text> : null}
				</View>
			)}
		</View>
	);
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
	return (
		<View style={styles.field}>
			<Text style={styles.fieldLabel}>{label}</Text>
			<Text style={[styles.fieldValue, mono && styles.mono]}>{value}</Text>
		</View>
	);
}

const styles = StyleSheet.create({
	section: {
		borderWidth: 1,
		borderColor: colors.border,
		borderRadius: 12,
		padding: 16,
		marginBottom: 16
	},
	sectionTitle: {
		fontSize: 12,
		fontWeight: '700',
		letterSpacing: 1,
		color: colors.textMuted,
		marginBottom: 12
	},
	row: { flexDirection: 'row', gap: 8 },
	flex: { flex: 1 },
	input: {
		borderWidth: 1,
		borderColor: colors.borderStrong,
		borderRadius: 8,
		paddingHorizontal: 12,
		paddingVertical: 10,
		fontSize: 14,
		color: colors.text
	},
	smallButton: {
		backgroundColor: colors.accent,
		borderRadius: 8,
		paddingHorizontal: 14,
		justifyContent: 'center',
		alignItems: 'center'
	},
	smallButtonText: { color: colors.buttonText, fontSize: 13, fontWeight: '600' },
	buttonDisabled: { opacity: 0.5 },
	error: {
		color: colors.danger,
		backgroundColor: colors.dangerBackground,
		borderWidth: 1,
		borderColor: colors.dangerBorder,
		borderRadius: 8,
		padding: 10,
		marginTop: 12,
		fontSize: 13
	},
	accountBlock: { marginTop: 16, borderTopWidth: 1, borderTopColor: colors.border, paddingTop: 16 },
	field: { marginBottom: 10 },
	fieldLabel: { fontSize: 12, color: colors.textMuted, marginBottom: 2 },
	fieldValue: { fontSize: 13, color: colors.text },
	mono: { fontFamily: Platform.select({ ios: 'Menlo', android: 'monospace', default: 'monospace' }) },
	actionsRow: { flexDirection: 'row', flexWrap: 'wrap', gap: 8, marginTop: 8 },
	pill: { borderWidth: 1, borderRadius: 8, paddingHorizontal: 12, paddingVertical: 8 },
	pillNeutral: { borderColor: colors.borderStrong },
	pillNeutralText: { color: colors.text, fontSize: 13 },
	pillDanger: { borderColor: '#b91c1c99' },
	pillDangerText: { color: colors.danger, fontSize: 13 },
	pillWarning: { borderColor: colors.warningBorder },
	pillWarningText: { color: colors.warning, fontSize: 13 }
});
